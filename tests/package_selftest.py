#!/usr/bin/env python3
"""诊断包留存自测：

- 上传/下载、内容寻址（同内容跨事件只存一份、按一份计字节）
- 同事件重复上传只留一个附件；换内容后旧包无挂载即删除
- FIFO 清退、已确认派查事件挂载保护、腾不够整单拒收且原附件照常下载
- 接收文件期间确认派查：清退以入库时的确认状态为准
- 入库前中断/入库失败：回滚后原附件仍可下载；重启后状态保留
- 配额解析、HTTP 413、spool 残留清理

用法: python3 tests/package_selftest.py
"""
import hashlib
import io
import os
import shutil
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from app import create_app  # noqa: E402
from app import packages  # noqa: E402
from app.db import connect  # noqa: E402

PASS = 0


def check(cond, label):
    global PASS
    assert cond, "FAIL: " + label
    PASS += 1
    print("  ok - " + label)


def q(db_path, sql, args=()):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(sql, args).fetchall()
    conn.close()
    return rows


def q1(db_path, sql, args=()):
    rows = q(db_path, sql, args)
    return rows[0] if rows else None


def make_event(app, event_no, pid):
    """造一条唯一匹配的事件，返回可用于确认的指纹。"""
    db_path = app.config["DATABASE"]
    conn = connect(db_path)
    from app import core
    core.upsert_runs(conn, [dict(run_no=event_no, boot_id="B", pid=pid,
                                 cgroup="/cg", start_ms=0, end_ms=10_000_000)])
    core.upsert_events(conn, [dict(event_no=event_no, boot_id="B", pid=pid,
                                   cgroup="/cg", time_ms=100, scope="memcg")])
    core.recompute_all(conn)
    conn.commit()
    fp = conn.execute(
        "SELECT fingerprint FROM attributions WHERE event_no=?",
        (event_no,)).fetchone()["fingerprint"]
    conn.close()
    return fp


def spool(app, data):
    path, digest, size = packages.spool_upload(
        io.BytesIO(data), app.config["BLOB_SPOOL_DIR"])
    return path, digest, size


def save(app, event_no, data, filename="pkg.bin"):
    """完整模拟一次入库（不经 HTTP），返回结果 dict。"""
    db_path = app.config["DATABASE"]
    path, digest, size = spool(app, data)
    conn = connect(db_path)
    try:
        result = packages.save_package(
            conn, event_no, path, digest, size, filename,
            "application/octet-stream", app.config["BLOB_QUOTA"])
    finally:
        conn.close()
    os.unlink(path)
    return result


def main():
    tmp = tempfile.mkdtemp(prefix="oom-pkg-selftest-")
    db_path = os.path.join(tmp, "oom.db")
    try:
        # 小配额：1000 字节，便于构造清退与拒收
        app = create_app({"DATABASE": db_path, "SECRET_KEY": "test",
                          "TESTING": True, "BLOB_QUOTA": 1000})
        c = app.test_client()
        for eno in (1, 2, 3, 4):
            make_event(app, eno, pid=1000 + eno)

        print("== 1. 配额解析与展示 ==")
        check(packages.parse_quota("100M") == 100 * 1024 ** 2, "100M 解析")
        check(packages.parse_quota("2g") == 2 * 1024 ** 3, "2g 解析")
        check(packages.parse_quota(" 512 ") == 512, "纯字节数解析")
        check(packages.human_size(1536) == "1.5 KiB", "human_size")
        for bad in ("abc", "-5", "9X"):
            try:
                packages.parse_quota(bad)
                raise AssertionError("应拒绝 " + bad)
            except packages.PackageError:
                pass
        check(True, "非法配额配置报错")

        print("== 2. 上传/下载，同内容跨事件只存一份 ==")
        data_a = b"A" * 300
        r = save(app, 1, data_a, "a.bin")
        check(r["status"] == "ingested" and r["evicted"] == [],
              "事件1 上传新包入库")
        blob_a = r["blob_id"]
        r = save(app, 2, data_a, "a-copy.bin")
        check(r["status"] == "remounted", "相同内容传到事件2 → remounted")
        check(q1(db_path, "SELECT COUNT(*) n FROM blobs")["n"] == 1,
              "全库仍只有 1 个内容包（只存一份）")
        check(q1(db_path, "SELECT SUM(size_bytes) n FROM blobs")["n"] == 300,
              "留存字节按一份计（300，不是 600）")
        check(q1(db_path,
                 "SELECT blob_id FROM event_attachments WHERE event_no=2")
              ["blob_id"] == blob_a, "事件2 挂到同一个 blob")
        # 经 HTTP 下载，两个事件都能下到同样内容
        for eno in (1, 2):
            resp = c.get("/events/{}/packages/download".format(eno))
            check(resp.status_code == 200 and resp.data == data_a,
                  "事件{} 下载内容与上传一致".format(eno))
        check(c.get("/events/1/packages").status_code == 200,
              "事件诊断包页面可访问")

        print("== 3. 同事件重复上传只留一个附件 ==")
        r = save(app, 1, data_a)
        check(r["status"] == "remounted" and r["replaced"] is None,
              "同事件重复上传相同内容：无替换、无新增")
        check(q1(db_path, "SELECT COUNT(*) n FROM event_attachments")["n"] == 2,
              "挂载仍只有事件1、2 两条")
        data_b = b"B" * 200
        r = save(app, 1, data_b, "b.bin")
        check(r["status"] == "ingested", "事件1 换内容：新包入库")
        check(q1(db_path,
                 "SELECT blob_id FROM event_attachments WHERE event_no=1")
              ["blob_id"] == r["blob_id"], "事件1 已改挂新包")
        check(q1(db_path, "SELECT COUNT(*) n FROM blobs")["n"] == 2,
              "事件2 仍持有 A 包，A 未被删除（仍有挂载）")
        data_c = b"C" * 100
        r = save(app, 2, data_c, "c.bin")
        check(q1(db_path, "SELECT digest FROM blobs WHERE id=?",
                 (blob_a,)) is None, "A 包失去全部挂载后立即删除")
        check(sorted(x["event_no"] for x in
                     q(db_path, "SELECT event_no FROM event_attachments"))
              == [1, 2], "挂载数仍为每事件一个")

        print("== 4. FIFO 清退（未确认事件，按首次入库顺序） ==")
        # 现状：B(200, 挂事件1)、C(100, 挂事件2)，已用 300；配额 1000
        # 传 D(900)：需腾 200；按 FIFO 退最早的 B(200) 即够（100+900=1000），C 保留
        data_d = b"D" * 900
        r = save(app, 3, data_d, "d.bin")
        check(r["status"] == "ingested", "大包 D 入库")
        evicted_ids = [b["id"] for b in r["evicted"]]
        check(len(evicted_ids) == 1
              and q1(db_path, "SELECT digest FROM blobs WHERE id=?",
                     (evicted_ids[0],)) is None,
              "恰好清退一个包（按需清退，腾够即停）")
        check(q1(db_path, "SELECT id FROM blobs WHERE digest=?",
                 (hashlib.sha256(data_b).hexdigest(),)) is None,
              "最早入库的 B 包被清退（FIFO 顺序）")
        check(q1(db_path, "SELECT id FROM blobs WHERE digest=?",
                 (hashlib.sha256(data_c).hexdigest(),)) is not None,
              "腾出 200 已够，C 包保留不扩大清退")
        check(q1(db_path,
                 "SELECT COUNT(*) n FROM event_attachments WHERE event_no=1")
              ["n"] == 0, "被清退的 B 在事件1上的挂载一并移除")
        check(q1(db_path, "SELECT blob_id FROM event_attachments WHERE event_no=2")
              is not None, "事件2 的 C 挂载不受影响")
        check(q1(db_path, "SELECT COALESCE(SUM(size_bytes),0) n FROM blobs")
              ["n"] == 1000, "清退后总占用恰好等于配额 1000")

        print("== 5. 已确认派查事件挂载的包受保护，腾不够整单拒收 ==")
        # 第4节末状态：C(100)挂事件2、D(900)挂事件3，共 1000 已满。
        # 确认事件3 → D 受保护。向「别的事件」(无附件的事件1) 传 E(200)：
        # 需腾 200；可清退的只有 C(100)，D 受保护不能退 → 腾不够，整单拒收。
        fp3 = make_event(app, 3, pid=1003)
        resp = c.post("/confirm", data={"event_no": 3, "fingerprint": fp3},
                      follow_redirects=True)
        check(b"\xe5\xb7\xb2\xe7\xa1\xae\xe8\xae\xa4" in resp.data,
              "事件3 已确认派查")
        data_e = b"E" * 200
        path, digest, size = spool(app, data_e)
        conn = connect(db_path)
        rejected = False
        try:
            try:
                packages.save_package(conn, 1, path, digest, size, "e.bin",
                                      "application/octet-stream",
                                      app.config["BLOB_QUOTA"])
            except packages.QuotaRejected as e:
                rejected = True
                check("留存上限" in e.detail and "拒收" in e.detail,
                      "拒收原因含配额说明")
        finally:
            conn.close()
            os.unlink(path)
        check(rejected, "受保护的 D 无法清退、C 不够腾 → 新包拒收")
        check(q1(db_path, "SELECT COUNT(*) n FROM blobs")["n"] == 2,
              "拒收后旧包一个没删")
        check(q1(db_path,
                 "SELECT blob_id FROM event_attachments WHERE event_no=3")
              ["blob_id"] is not None, "拒收后事件3 原挂载仍在")
        check(q1(db_path,
                 "SELECT blob_id FROM event_attachments WHERE event_no=2")
              ["blob_id"] is not None, "拒收后事件2 的 C 挂载仍在")
        resp = c.get("/events/3/packages/download")
        check(resp.status_code == 200 and resp.data == data_d,
              "拒收后原附件 D 照常下载")
        # 对照：若事件3 未确认，同样的 E 可清退 C+D 后入库（保护确实在起作用）
        conn = connect(db_path)
        conn.execute("UPDATE confirmations SET state='revoked', revoked_at=? "
                     "WHERE event_no=3 AND state='active'",
                     (packages.now_iso(),))
        conn.commit()
        conn.close()
        r = save(app, 1, data_e, "e.bin")
        check(r["status"] == "ingested" and len(r["evicted"]) == 2,
              "解除确认后 C、D 两个未受保护包均可被 FIFO 清退，E 入库")
        check(sorted(b["size_bytes"] for b in r["evicted"]) == [100, 900],
              "被清退的正是 C(100) 与 D(900)")
        check(q1(db_path, "SELECT id FROM blobs WHERE digest=?",
                 (hashlib.sha256(data_e).hexdigest(),)) is not None,
              "E 已入库")
        check(q1(db_path, "SELECT COALESCE(SUM(size_bytes),0) n FROM blobs")
              ["n"] == 200, "清退后只剩 E（200 字节）")

        print("== 6. 接收文件期间确认派查：以入库时确认状态为准 ==")
        # 当前：E(200) 挂事件1，配额 1000。给未确认的事件4 挂 G(700)，用满 900。
        make_event(app, 4, pid=1004)
        data_g = b"G" * 700
        save(app, 4, data_g, "g.bin")
        # F(150) 先完整接收到 spool（模拟「接收文件期间」），此时尚未入库
        data_f = b"F" * 150
        path, digest, size = spool(app, data_f)
        # 接收期间，值班员对事件4 确认派查 → G 此刻起受保护
        fp4 = make_event(app, 4, pid=1004)
        c.post("/confirm", data={"event_no": 4, "fingerprint": fp4})
        check(q1(db_path,
                 "SELECT state FROM confirmations WHERE event_no=4 AND "
                 "state='active'") is not None, "接收期间事件4 完成确认")
        conn = connect(db_path)
        try:
            try:
                # 入库时刻：已用 900，F 需再腾 50；E 可退 200 本够，
                # 但 G 受保护、E 退掉后 700+150=850 仍 ≤1000，应能成功——
                # 这里精确构造为：把 E 也保护起来，使无包可退。
                packages.save_package(conn, 4, path, digest, size, "f.bin",
                                      "application/octet-stream",
                                      app.config["BLOB_QUOTA"])
                raised_when_protected = False
            except packages.QuotaRejected:
                raised_when_protected = True
        finally:
            conn.close()
        # 事件4 替换自己的 G：G 释放 700，F 仅 150，必然放得下 → 不应拒收
        check(not raised_when_protected,
              "替换已确认事件自己的附件：旧包释放后空间足够，正常入库")
        os.unlink(path)
        check(q1(db_path, "SELECT digest FROM blobs b JOIN event_attachments ea "
                          "ON ea.blob_id=b.id WHERE ea.event_no=4")["digest"]
              == hashlib.sha256(data_f).hexdigest(),
              "事件4 已改挂 F，确认状态不变")

        # 真正的「接收中确认改变清退结果」对照：
        # 事件5 未确认挂 H(700)，向事件1（挂 E=200）传 I(150)。
        make_event(app, 5, pid=1005)
        data_h = b"H" * 700
        save(app, 5, data_h, "h.bin")  # F150 + H700 = 850
        path, digest, size = spool(app, b"I" * 150)
        # 未确认时入库：需腾 0（850+150=1000 正好），成功
        conn = connect(db_path)
        try:
            packages.save_package(conn, 1, path, digest, size, "i.bin",
                                  "application/octet-stream",
                                  app.config["BLOB_QUOTA"])
            ok_without_confirm = True
        except packages.QuotaRejected:
            ok_without_confirm = False
        finally:
            conn.close()
            os.unlink(path)
        check(ok_without_confirm, "未确认时新包 I 可入库（空间恰好够）")

        # 重做：把 H 所在的事件5 确认，再传一个需要清退 H 的包 → H 受保护被拒
        fp5 = make_event(app, 5, pid=1005)
        c.post("/confirm", data={"event_no": 5, "fingerprint": fp5})
        path, digest, size = spool(app, b"J" * 300)  # 现 1000 满，需腾 300
        conn = connect(db_path)
        try:
            try:
                # 候选：F(150,事件4 已确认→受保护)、I(150,事件1 未确认)、
                # H(700,事件5 已确认→受保护)。只能退 I 的 150，仍差 150 → 拒收
                packages.save_package(conn, 2, path, digest, size, "j.bin",
                                      "application/octet-stream",
                                      app.config["BLOB_QUOTA"])
                raised_when_confirmed = False
            except packages.QuotaRejected:
                raised_when_confirmed = True
        finally:
            conn.close()
            os.unlink(path)
        check(raised_when_confirmed,
              "接收/入库前完成确认：受保护包不能退，腾不够则拒收")
        check(q1(db_path, "SELECT COUNT(*) n FROM blobs")["n"] == 3,
              "拒收后 F、I、H 三个包原样保留")
        check(c.get("/events/5/packages/download").data == data_h,
              "已确认事件5 的 H 包拒收后仍可下载")

        print("== 7. 入库前中断与入库失败：回滚、重启可下载、spool 清理 ==")
        # 7a. spool 接收后直接放弃（模拟入库前进程中断）：重启清残留，库不变
        before = q1(db_path, "SELECT COUNT(*) n FROM blobs")["n"]
        path, digest, size = spool(app, b"X" * 10)
        check(os.path.isfile(path), "临时文件已落 spool 目录")
        check(packages.cleanup_spool(app.config["BLOB_SPOOL_DIR"]) >= 1
              and not os.path.exists(path), "启动清理删除残留 .part")
        check(q1(db_path, "SELECT COUNT(*) n FROM blobs")["n"] == before,
              "中断未写入任何 blob")
        # 7b. 入库函数内部失败（伪造 spool 大小不符）→ 整体回滚
        path, digest, size = spool(app, b"Y" * 10)
        conn = connect(db_path)
        try:
            try:
                packages.save_package(conn, 1, path, digest, size + 999,
                                      "y.bin", "application/octet-stream",
                                      app.config["BLOB_QUOTA"])
                raised = False
            except packages.PackageError:
                raised = True
        finally:
            conn.close()
            os.unlink(path)
        check(raised, "大小校验失败抛 PackageError")
        check(q1(db_path, "SELECT COUNT(*) n FROM blobs")["n"] == before,
              "失败回滚：blob 数不变")
        # 7c. 事件不存在
        path, digest, size = spool(app, b"Z" * 10)
        conn = connect(db_path)
        try:
            try:
                packages.save_package(conn, 999, path, digest, size, "z.bin",
                                      "application/octet-stream",
                                      app.config["BLOB_QUOTA"])
                raised = False
            except packages.PackageError:
                raised = True
        finally:
            conn.close()
            os.unlink(path)
        check(raised, "不存在的事件上传被拒")

        print("== 8. 重启持久化与 HTTP 413 ==")
        # 第6节末：F(150)挂已确认事件4、I(150)挂事件1、H(700)挂已确认事件5，共 1000
        n_before_restart = q1(db_path, "SELECT COUNT(*) n FROM blobs")["n"]
        app2 = create_app({"DATABASE": db_path, "SECRET_KEY": "test",
                           "TESTING": True, "BLOB_QUOTA": 1000})
        c2 = app2.test_client()
        resp = c2.get("/events/5/packages/download")
        check(resp.status_code == 200 and resp.data == data_h,
              "重启后已确认事件5 的 H 包仍可下载")
        resp = c2.get("/events/4/packages/download")
        check(resp.status_code == 200 and resp.data == data_f,
              "重启后事件4 的 F 包仍可下载")
        check(q1(db_path, "SELECT state FROM confirmations WHERE event_no=5 "
                          "AND state='active'") is not None,
              "重启后确认状态仍在（保护继续有效）")
        check(q1(db_path, "SELECT COUNT(*) n FROM blobs")["n"]
              == n_before_restart, "重启后 blob 数量不变")
        # 超过 MAX_CONTENT_LENGTH（=配额）的请求在 HTTP 层直接 413
        resp = c2.post(
            "/events/1/packages",
            data={"package": (io.BytesIO(b"Q" * 1001), "big.bin")},
            content_type="multipart/form-data")
        check(resp.status_code == 413 and "留存上限".encode() in resp.data,
              "超配额请求返回 413 友好页面")
        check(q1(db_path, "SELECT COUNT(*) n FROM blobs")["n"]
              == n_before_restart, "413 未落任何数据")
        # 空文件
        resp = c2.post(
            "/events/1/packages",
            data={"package": (io.BytesIO(b""), "empty.bin")},
            content_type="multipart/form-data", follow_redirects=True)
        check("为空".encode() in resp.data, "空文件被拒并提示")

        print("== 9. 替换受保护包：用户主动换挂允许，旧包无挂载即删 ==")
        # 事件5 已确认且挂 H；主动上传新内容 K 替换 H
        # （保护只约束 FIFO 清退，不约束该事件本人主动替换）
        data_k = b"K" * 30
        r = save(app, 5, data_k, "k.bin")
        check(r["status"] == "ingested" and r["replaced"] is not None,
              "已确认事件主动替换附件成功")
        check(q1(db_path, "SELECT id FROM blobs WHERE digest=?",
                 (hashlib.sha256(data_h).hexdigest(),)) is None,
              "H 失去唯一挂载后删除（字节释放）")
        check(c2.get("/events/5/packages/download").data == data_k,
              "事件5 现在下载到新包 K")
        check(q1(db_path,
                 "SELECT state FROM confirmations WHERE event_no=5 AND "
                 "state='active'") is not None, "确认状态不受换挂影响")
        # 换挂后空间释放：F150 + I150 + K30 = 330，再传 600 的包应能入库
        r = save(app, 2, b"L" * 600, "l.bin")
        check(r["status"] == "ingested" and r["evicted"] == [],
              "释放空间后新包 L 无需清退即可入库")
        check(q1(db_path, "SELECT COALESCE(SUM(size_bytes),0) n FROM blobs")
              ["n"] == 930, "最终占用 330+600=930，未超配额")

        print("== 10. 共享包替换：旧包仍有其他挂载时进入 FIFO 评估 ==")
        # 重置一个干净小场景：M(300) 同时挂事件1、2；配额 1000，已用 300。
        conn = connect(db_path)
        conn.execute("DELETE FROM blobs")
        conn.commit()
        conn.close()
        data_m = b"M" * 300
        save(app, 1, data_m, "m.bin")
        save(app, 2, data_m)  # remount：M 现挂事件1、2，仅 1 份 300 字节
        check(q1(db_path, "SELECT COUNT(*) n FROM blobs")["n"] == 1,
              "M 全库一份")
        # 向事件2 传 N(800)：需腾 100；M 不会因替换被孤立（事件1 仍挂），
        # M 未受保护（事件1、2 均无有效确认）→ 应作为 FIFO 候选被清退，
        # 其在事件1 上的挂载也一并移除，N 入库。
        data_n = b"N" * 800
        r = save(app, 2, data_n, "n.bin")
        check(r["status"] == "ingested" and len(r["evicted"]) == 1
              and r["evicted"][0]["events"] == [1, 2],
              "共享的 M 被 FIFO 清退，且记录其全部挂载事件 [1,2]")
        check(q1(db_path, "SELECT id FROM blobs WHERE digest=?",
                 (hashlib.sha256(data_m).hexdigest(),)) is None,
              "共享包 M 已删除")
        check(q1(db_path, "SELECT COUNT(*) n FROM event_attachments "
                          "WHERE event_no=1")["n"] == 0,
              "M 在事件1 上的挂载随清退移除")
        check(c.get("/events/2/packages/download").data == data_n,
              "事件2 下载到新包 N")
        check(q1(db_path, "SELECT COALESCE(SUM(size_bytes),0) n FROM blobs")
              ["n"] == 800, "清退后只剩 N（800 字节）")
        # 对照：若事件1 已确认，则 M 受保护，同样的 N 应被拒收
        save(app, 1, data_m)  # 重新让事件1 挂上 M
        fp1 = make_event(app, 1, pid=1001)
        c.post("/confirm", data={"event_no": 1, "fingerprint": fp1})
        path, digest, size = spool(app, b"O" * 800)
        conn = connect(db_path)
        try:
            try:
                packages.save_package(conn, 2, path, digest, size, "o.bin",
                                      "application/octet-stream",
                                      app.config["BLOB_QUOTA"])
                raised = False
            except packages.QuotaRejected:
                raised = True
        finally:
            conn.close()
            os.unlink(path)
        check(raised, "事件1 确认后共享包 M 受保护，事件2 的 O 被拒收")
        check(q1(db_path, "SELECT COUNT(*) n FROM blobs")["n"] == 1,
              "拒收后 M 原样保留（O 未入库）")
        check(c.get("/events/1/packages/download").data == data_m,
              "已确认事件1 的 M 拒收后仍可下载")

        print("\n全部 {} 项检查通过".format(PASS))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
