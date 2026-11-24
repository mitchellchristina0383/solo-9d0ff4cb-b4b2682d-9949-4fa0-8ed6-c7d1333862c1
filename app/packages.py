"""现场诊断包的留存、挂载与按确认状态清退（不依赖 Flask，便于自测）。

留存规则：

- 诊断包按内容（sha256）寻址：同一份内容只存一份字节，可挂到多个事件下，
  留存字节按这一份计；重复上传到同一事件只保留一个挂载。
- 每个事件至多挂一个附件；重新上传会替换挂载，旧包因此没有任何挂载时立即删除。
- 已确认派查（confirmations.state='active'）的事件只要还挂着某个包，该包受保护、
  不能被清退。
- 新包放不下时，按首次入库顺序（blobs.id 自增）清退未受保护的其余包，并移除
  被清退包的所有挂载；能否清退以新包入库事务开始时的确认状态为准。
- 腾够空间才让「新包入库 + 挂载 + 整批清退」在一个事务内一并生效；腾不够则
  整体拒收（不删任何旧包、不动任何挂载）。
"""
import hashlib
import os
import re
import shutil
import tempfile

from .core import now_iso

CHUNK = 1024 * 1024  # 流式读写块大小：1 MiB


class PackageError(Exception):
    """诊断包上传/入库失败（非配额类）。"""


class QuotaRejected(Exception):
    """留存上限不足，新包被拒收。``detail`` 为面向页面的中文原因。"""

    def __init__(self, detail):
        super().__init__(detail)
        self.detail = detail


# ---------------------------------------------------------------- 配置与展示

_UNITS = {"": 1, "b": 1, "k": 1024, "kb": 1024, "m": 1024 ** 2, "mb": 1024 ** 2,
          "g": 1024 ** 3, "gb": 1024 ** 3}


def parse_quota(text):
    """解析留存上限，如 "100M"、"2g"、"524288000"。返回字节数（正整数）。"""
    if text is None:
        raise PackageError("留存上限未配置")
    m = re.fullmatch(r"\s*(\d+)\s*([a-zA-Z]*)\s*", str(text))
    if not m:
        raise PackageError("留存上限配置无法解析: {!r}".format(text))
    unit = m.group(2).lower()
    if unit not in _UNITS:
        raise PackageError("留存上限单位无法识别: {!r}".format(text))
    value = int(m.group(1)) * _UNITS[unit]
    if value <= 0:
        raise PackageError("留存上限必须为正: {!r}".format(text))
    return value


def human_size(n):
    """字节数转人类可读（二进制单位，保留一位小数）。"""
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            if unit == "B":
                return "{} B".format(int(n))
            return "{:.1f} {}".format(n, unit)
        n /= 1024


def safe_filename(name):
    """去掉路径成分与控制字符，保留中文等普通字符；空名回退为占位名。"""
    name = os.path.basename(str(name or "").replace("\\", "/")).strip()
    name = re.sub(r"[\x00-\x1f]", "", name)
    return name or "package.bin"


# ---------------------------------------------------------------- 接收（落盘暂存）

def spool_upload(stream, spool_dir):
    """把上传流完整读到 spool_dir 下的临时文件，边读边算 sha256。

    返回 (spool_path, digest, size_bytes)。入库前中断只留下临时文件，
    不影响数据库里的任何现有附件；残留临时文件在应用启动时清理。
    """
    os.makedirs(spool_dir, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix="incoming-", suffix=".part", dir=spool_dir)
    h = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = stream.read(CHUNK)
                if not chunk:
                    break
                h.update(chunk)
                size += len(chunk)
                out.write(chunk)
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    if size == 0:
        os.unlink(path)
        raise PackageError("上传文件为空，未接收")
    return path, h.hexdigest(), size


def cleanup_spool(spool_dir):
    """启动时清理上次接收中断可能残留的 .part 临时文件。"""
    if not os.path.isdir(spool_dir):
        return 0
    removed = 0
    for name in os.listdir(spool_dir):
        if name.startswith("incoming-") and name.endswith(".part"):
            try:
                os.unlink(os.path.join(spool_dir, name))
                removed += 1
            except OSError:
                pass
    return removed


# ---------------------------------------------------------------- 入库与清退

def _protected_blob_ids(conn):
    """当前仍挂在「已确认派查」事件上的包 id（以入库时刻的确认状态为准）。"""
    return {r["blob_id"] for r in conn.execute(
        """SELECT DISTINCT ea.blob_id
             FROM event_attachments ea
             JOIN confirmations c ON c.event_no = ea.event_no
            WHERE c.state = 'active'""")}


def _used_bytes(conn):
    return conn.execute(
        "SELECT COALESCE(SUM(size_bytes), 0) AS n FROM blobs").fetchone()["n"]


def save_package(conn, event_no, spool_path, digest, size_bytes,
                 filename, content_type, quota):
    """单事务完成新包入库、事件挂载与按 FIFO 清退。

    返回 dict：
      status     "ingested"（新包入库）/ "remounted"（内容已存在，仅挂/换挂载）
      blob_id, digest, size_bytes, filename, mounted_at
      evicted    被清退的 [{id, filename, size_bytes, events:[event_no...]}]
      replaced   被替换掉的旧挂载 blob_id（无则 None）
    配额不足时抛 QuotaRejected；其他失败抛 PackageError。
    调用方负责 commit/rollback（本函数不提交）。
    """
    # 所有读写都放在 BEGIN IMMEDIATE 之后：sqlite3 会在第一条 DML 前自动开
    # 延迟事务，若先 SELECT 再显式 BEGIN 会报 "cannot start a transaction
    # within a transaction"。立即拿写锁后，确认状态以这一刻为准。
    conn.execute("BEGIN IMMEDIATE")
    try:
        ev = conn.execute("SELECT 1 FROM events WHERE event_no = ?",
                          (event_no,)).fetchone()
        if ev is None:
            raise PackageError("事件 {} 不存在".format(event_no))
        if not os.path.isfile(spool_path):
            raise PackageError("接收的临时文件已丢失，入库中止")
        actual_size = os.path.getsize(spool_path)
        if actual_size != size_bytes or actual_size <= 0:
            raise PackageError(
                "接收文件大小不一致（登记 {} / 磁盘 {}），入库中止".format(
                    size_bytes, actual_size))

        existing = conn.execute(
            "SELECT * FROM blobs WHERE digest = ?", (digest,)).fetchone()
        old = conn.execute(
            "SELECT blob_id FROM event_attachments WHERE event_no = ?",
            (event_no,)).fetchone()
        old_blob_id = old["blob_id"] if old else None
        now = now_iso()
        evicted = []

        # ---- 情况 A：内容已在库，只调整挂载，不新增字节、无需清退 ----
        if existing is not None:
            blob_id = existing["id"]
            replaced = None
            if old_blob_id != blob_id:
                # 先摘旧挂载行（保留旧 blob），再写新挂载，最后才删孤立 blob。
                if old_blob_id is not None:
                    _unmount_event_blob(conn, event_no, old_blob_id)
                conn.execute(
                    """INSERT INTO event_attachments (event_no, blob_id, mounted_at)
                       VALUES (?, ?, ?)
                       ON CONFLICT(event_no) DO UPDATE SET
                           blob_id = excluded.blob_id,
                           mounted_at = excluded.mounted_at""",
                    (event_no, blob_id, now))
                if old_blob_id is not None:
                    _drop_blob_if_orphan(conn, old_blob_id)
                    replaced = old_blob_id
            conn.commit()
            return {"status": "remounted", "blob_id": blob_id,
                    "digest": digest, "size_bytes": existing["size_bytes"],
                    "filename": existing["filename"], "mounted_at": now,
                    "evicted": evicted, "replaced": replaced}

        # ---- 情况 B：新内容。先算需要腾出多少字节 ----
        # 替换场景：先假设本事件的旧挂载被摘掉。旧 blob 若再无其他挂载会被
        # 删除（字节确定释放，且不参与 FIFO）；若仍有其他事件挂载则保留，
        # 字节继续计入，是否清退取决于它是否受保护，照常进入 FIFO 候选。
        released_by_old = 0  # 替换本事件旧包能确定释放的字节
        old_becomes_orphan = False
        if old_blob_id is not None:
            mounts = conn.execute(
                "SELECT COUNT(*) n FROM event_attachments WHERE blob_id = ?",
                (old_blob_id,)).fetchone()["n"]
            if mounts <= 1:  # 只有本事件这一个挂载，摘下后即孤立
                old_becomes_orphan = True
                released_by_old = conn.execute(
                    "SELECT size_bytes FROM blobs WHERE id = ?",
                    (old_blob_id,)).fetchone()["size_bytes"]
        # 替换后、清退前的占用 = 现有总字节 - 旧包确定释放的字节。
        # 需额外清退 = 该占用 + 新包 - 配额（不为负）。
        need = _used_bytes(conn) - released_by_old + size_bytes - quota
        if need < 0:
            need = 0

        protected = _protected_blob_ids(conn)
        if old_becomes_orphan:
            # 确定会被孤立删除的旧包不进 FIFO（其字节已计入 released_by_old）。
            candidates = conn.execute(
                "SELECT * FROM blobs WHERE id <> ? ORDER BY id ASC",
                (old_blob_id,)).fetchall()
        else:
            # 旧包仍有其他挂载：保留在候选中，受保护则跳过、否则可被 FIFO 清退。
            candidates = conn.execute(
                "SELECT * FROM blobs ORDER BY id ASC").fetchall()

        plan = []
        freed = 0
        if need > 0:  # need=0 表示现有空间足够，一个包都不能清退
            for b in candidates:
                if b["id"] in protected:
                    continue  # 挂在已确认事件上的包保留
                plan.append(b)
                freed += b["size_bytes"]
                if freed >= need:
                    break

        if need > 0 and freed < need:
            short = need - freed
            conn.rollback()
            raise QuotaRejected(
                "留存上限 {quota} 不足：新包 {new}，当前已留存 {used}，"
                "可清退 {freed}，仍差 {short}；已确认派查事件挂载的诊断包"
                "不能清退。本次拒收，原有附件不受影响、仍可下载。".format(
                    quota=human_size(quota), new=human_size(size_bytes),
                    used=human_size(_used_bytes(conn)),
                    freed=human_size(freed), short=human_size(short)))

        # ---- 腾够空间：整批清退与新包入库在同一事务内一并生效 ----
        for b in plan:
            mount_events = [r["event_no"] for r in conn.execute(
                "SELECT event_no FROM event_attachments WHERE blob_id = ? "
                "ORDER BY event_no", (b["id"],))]
            conn.execute("DELETE FROM blobs WHERE id = ?", (b["id"],))
            evicted.append({"id": b["id"], "filename": b["filename"],
                            "size_bytes": b["size_bytes"], "events": mount_events})

        # 先摘掉本事件的旧挂载行（旧 blob 暂留，避免级联误删），
        # 新包落盘并挂好后，再把失去全部挂载的旧 blob 删掉。
        if old_blob_id is not None:
            _unmount_event_blob(conn, event_no, old_blob_id)
        cur = conn.execute(
            "INSERT INTO blobs (digest, size_bytes, filename, content_type, "
            "data, ingested_at) VALUES (?, ?, ?, ?, zeroblob(?), ?)",
            (digest, size_bytes, filename, content_type, size_bytes, now))
        blob_id = cur.lastrowid
        with conn.blobopen("blobs", "data", blob_id, readonly=False) as blob:
            with open(spool_path, "rb") as f:
                shutil.copyfileobj(f, blob, length=CHUNK)
        conn.execute(
            """INSERT INTO event_attachments (event_no, blob_id, mounted_at)
               VALUES (?, ?, ?)
               ON CONFLICT(event_no) DO UPDATE SET
                   blob_id = excluded.blob_id,
                   mounted_at = excluded.mounted_at""",
            (event_no, blob_id, now))
        if old_blob_id is not None:
            _drop_blob_if_orphan(conn, old_blob_id)
        conn.commit()
        return {"status": "ingested", "blob_id": blob_id, "digest": digest,
                "size_bytes": size_bytes, "filename": filename,
                "mounted_at": now, "evicted": evicted,
                "replaced": old_blob_id}
    except QuotaRejected:
        raise
    except Exception:
        # 任何中途失败都整体回滚：原附件与挂载保持原样，重启后仍可下载。
        if conn.in_transaction:
            conn.rollback()
        raise


def _drop_blob_if_orphan(conn, blob_id):
    """包失去全部挂载时立即删除（字节不再计入留存）。

    仅在调用方已通过 _unmount_event_blob 摘掉本事件旧挂载、并把事件挂到新
    blob 之后调用，确保外键级联不会误删任何仍有效的挂载行。
    """
    n = conn.execute(
        "SELECT COUNT(*) n FROM event_attachments WHERE blob_id = ?",
        (blob_id,)).fetchone()["n"]
    if n == 0:
        conn.execute("DELETE FROM blobs WHERE id = ?", (blob_id,))


def _unmount_event_blob(conn, event_no, blob_id):
    """删除事件在 blob_id 上的旧挂载行（blob 本身先保留）。

    必须在把事件 upsert 到新 blob **之前**调用：upsert 会直接把事件行改指新
    blob，之后再按 (event_no, 旧blob) 删行将删不到，而旧 blob 又会被当成孤立
    blob 删除，外键级联会误删事件的新挂载行。孤立 blob 的统一清理由
    _drop_blob_if_orphan 在新挂载写好后完成。
    """
    conn.execute(
        "DELETE FROM event_attachments WHERE event_no = ? AND blob_id = ?",
        (event_no, blob_id))


# ---------------------------------------------------------------- 查询

def event_attachment(conn, event_no):
    """事件当前挂载的附件（含包信息），无挂载返回 None。"""
    return conn.execute(
        """SELECT ea.event_no, ea.mounted_at, b.id AS blob_id, b.digest,
                  b.size_bytes, b.filename, b.content_type, b.ingested_at
             FROM event_attachments ea JOIN blobs b ON b.id = ea.blob_id
            WHERE ea.event_no = ?""", (event_no,)).fetchone()


def quota_usage(conn):
    """返回 (已留存字节, 包个数)。"""
    row = conn.execute(
        "SELECT COALESCE(SUM(size_bytes),0) AS used, COUNT(*) AS n "
        "FROM blobs").fetchone()
    return row["used"], row["n"]


def blob_mount_events(conn, blob_id):
    """一个包当前挂载在哪些事件上（按事件号）。"""
    return [r["event_no"] for r in conn.execute(
        "SELECT event_no FROM event_attachments WHERE blob_id = ? "
        "ORDER BY event_no", (blob_id,))]


def open_blob_stream(db_path, blob_id):
    """返回 (生成器, 大小)：用独立连接分块产出 blob，读完自动关闭。

    独立连接避免请求 teardown 提前关闭 g 里的连接；WAL 模式下读不会阻塞
    其他连接的写入。blob 不存在时抛 PackageError。
    """
    from .db import connect  # 延迟导入，保持本模块不依赖 Flask 上下文

    conn = connect(db_path)
    size = conn.execute(
        "SELECT size_bytes FROM blobs WHERE id = ?", (blob_id,)).fetchone()
    if size is None:
        conn.close()
        raise PackageError("诊断包 #{} 不存在".format(blob_id))

    def generate():
        try:
            with conn.blobopen("blobs", "data", blob_id, readonly=True) as blob:
                while True:
                    chunk = blob.read(CHUNK)
                    if not chunk:
                        break
                    yield chunk
        finally:
            conn.close()

    return generate(), size["size_bytes"]
