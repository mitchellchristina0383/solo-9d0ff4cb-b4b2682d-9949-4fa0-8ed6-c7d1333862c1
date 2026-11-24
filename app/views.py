"""页面与表单路由。"""
import os
import sqlite3

from urllib.parse import quote as url_quote

from flask import (Blueprint, Response, abort, current_app, flash, redirect,
                   render_template, request, url_for)
from werkzeug.utils import secure_filename

from . import core, packages
from .db import get_db

bp = Blueprint("main", __name__)


def _flash_recompute(stats):
    msgs = []
    if stats["changed"]:
        msgs.append("归属结论已重核（更新 {} 条）".format(len(stats["changed"])))
    for event_no, reason in stats["revoked"]:
        msgs.append("事件 {} 的原确认已撤销：{}".format(event_no, reason))
    return msgs


@bp.route("/")
def index():
    db = get_db()
    events = db.execute(
        """SELECT e.event_no, e.boot_id, e.pid, e.cgroup, e.time_ms, e.scope,
                  a.status, a.run_no AS attr_run_no, a.match_count, a.fingerprint
           FROM events e LEFT JOIN attributions a USING (event_no)
           ORDER BY e.event_no"""
    ).fetchall()
    active, revoked = {}, {}
    for c in db.execute("SELECT * FROM confirmations ORDER BY id").fetchall():
        if c["state"] == "active":
            active[c["event_no"]] = c
        else:
            revoked[c["event_no"]] = c  # 取最近一次被撤销的确认
    return render_template("index.html", events=events,
                           active=active, revoked=revoked)


@bp.route("/import", methods=["GET", "POST"])
def import_csv():
    if request.method == "POST":
        kind = request.form.get("kind")
        f = request.files.get("file")
        if f is None or not f.filename:
            flash("请选择要导入的 CSV 文件", "error")
            return redirect(url_for(".import_csv"))
        try:
            text = f.read().decode("utf-8-sig")
        except UnicodeDecodeError:
            flash("文件编码需为 UTF-8", "error")
            return redirect(url_for(".import_csv"))
        db = get_db()
        try:
            if kind == "runs":
                ins, upd = core.upsert_runs(db, core.parse_runs_csv(text))
                what = "运行记录：新增 {} 条，更正 {} 条".format(ins, upd)
            elif kind == "events":
                ins, upd = core.upsert_events(db, core.parse_events_csv(text))
                what = "OOM 摘要：新增 {} 条，更正 {} 条".format(ins, upd)
            else:
                flash("未知导入类型", "error")
                return redirect(url_for(".import_csv"))
            stats = core.recompute_all(db)
            db.commit()
        except core.DataError as e:
            db.rollback()
            flash("导入失败，未写入任何数据：{}".format(e), "error")
            return redirect(url_for(".import_csv"))
        for m in _flash_recompute(stats):
            flash(m, "error")
        flash("导入完成（{}）".format(what), "ok")
        return redirect(url_for(".index"))
    return render_template("import.html")


@bp.route("/confirm", methods=["POST"])
def confirm():
    try:
        event_no = int(request.form.get("event_no", ""))
    except ValueError:
        flash("确认请求不合法", "error")
        return redirect(url_for(".index"))
    fp = request.form.get("fingerprint", "")
    db = get_db()
    try:
        result = core.confirm_event(db, event_no, fp)
        db.commit()
    except core.ConfirmRejected as e:
        db.rollback()
        flash("确认被拒绝：{}".format(e), "error")
        return redirect(url_for(".index"))
    except sqlite3.IntegrityError:
        # 并发下另一请求已确认（唯一索引兜底）
        db.rollback()
        flash("事件 {} 已被确认".format(event_no), "ok")
        return redirect(url_for(".index"))
    if result == "already":
        flash("事件 {} 已是确认状态".format(event_no), "ok")
    else:
        flash("事件 {} 已确认，可派查".format(event_no), "ok")
    return redirect(url_for(".index"))


@bp.route("/runs")
def runs():
    rows = get_db().execute(
        "SELECT * FROM runs ORDER BY run_no").fetchall()
    return render_template("runs.html", runs=rows)


@bp.route("/runs/<int:run_no>/edit", methods=["GET", "POST"])
def edit_run(run_no):
    db = get_db()
    run = db.execute(
        "SELECT * FROM runs WHERE run_no = ?", (run_no,)).fetchone()
    if request.method == "POST":
        try:
            row = core.run_from_strings(
                dict(request.form, run_no=run_no))
        except core.DataError as e:
            flash(str(e), "error")
            return render_template("run_edit.html", run_no=run_no,
                                   is_new=run is None, form=request.form)
        core.upsert_runs(db, [row])
        stats = core.recompute_all(db)
        db.commit()
        for m in _flash_recompute(stats):
            flash(m, "error")
        flash("运行记录 {} 已保存".format(run_no), "ok")
        return redirect(url_for(".runs"))
    form = dict(run) if run else {}
    return render_template("run_edit.html", run_no=run_no,
                           is_new=run is None, form=form)


@bp.route("/events")
def events():
    rows = get_db().execute(
        "SELECT * FROM events ORDER BY event_no").fetchall()
    return render_template("events.html", events=rows)


@bp.route("/events/<int:event_no>/edit", methods=["GET", "POST"])
def edit_event(event_no):
    db = get_db()
    ev = db.execute(
        "SELECT * FROM events WHERE event_no = ?", (event_no,)).fetchone()
    if request.method == "POST":
        try:
            row = core.event_from_strings(
                dict(request.form, event_no=event_no))
        except core.DataError as e:
            flash(str(e), "error")
            return render_template("event_edit.html", event_no=event_no,
                                   is_new=ev is None, form=request.form)
        core.upsert_events(db, [row])
        stats = core.recompute_all(db)
        db.commit()
        for m in _flash_recompute(stats):
            flash(m, "error")
        flash("事件 {} 已保存".format(event_no), "ok")
        return redirect(url_for(".events"))
    form = dict(ev) if ev else {}
    return render_template("event_edit.html", event_no=event_no,
                           is_new=ev is None, form=form)


# ---------------------------------------------------------------- 现场诊断包

def _get_event_or_404(db, event_no):
    ev = db.execute(
        """SELECT e.*, a.status, a.run_no AS attr_run_no, a.match_count
             FROM events e LEFT JOIN attributions a USING (event_no)
            WHERE e.event_no = ?""", (event_no,)).fetchone()
    if ev is None:
        abort(404)
    return ev


@bp.route("/events/<int:event_no>/packages")
def event_packages(event_no):
    db = get_db()
    ev = _get_event_or_404(db, event_no)
    conf = db.execute(
        "SELECT * FROM confirmations WHERE event_no = ? AND state = 'active'",
        (event_no,)).fetchone()
    att = packages.event_attachment(db, event_no)
    mounts = (packages.blob_mount_events(db, att["blob_id"]) if att else [])
    used, blob_count = packages.quota_usage(db)
    quota = current_app.config["BLOB_QUOTA"]
    return render_template(
        "event_packages.html", ev=ev, conf=conf, att=att, mounts=mounts,
        used=used, blob_count=blob_count, quota=quota,
        used_h=packages.human_size(used), quota_h=packages.human_size(quota))


@bp.route("/events/<int:event_no>/packages", methods=["POST"])
def upload_package(event_no):
    db = get_db()
    if db.execute("SELECT 1 FROM events WHERE event_no = ?",
                  (event_no,)).fetchone() is None:
        abort(404)
    f = request.files.get("package")
    if f is None or not f.filename:
        flash("请选择要上传的诊断包文件", "error")
        return redirect(url_for(".event_packages", event_no=event_no))

    spool_path = None
    try:
        spool_path, digest, size = packages.spool_upload(
            f.stream, current_app.config["BLOB_SPOOL_DIR"])
        result = packages.save_package(
            db, event_no, spool_path, digest, size,
            packages.safe_filename(f.filename), f.mimetype,
            current_app.config["BLOB_QUOTA"])
    except packages.QuotaRejected as e:
        db.rollback()
        flash("诊断包被拒收：" + e.detail, "error")
        return redirect(url_for(".event_packages", event_no=event_no))
    except packages.PackageError as e:
        db.rollback()
        flash("诊断包上传失败，未写入任何数据：{}".format(e), "error")
        return redirect(url_for(".event_packages", event_no=event_no))
    finally:
        # spool_upload 失败（如空文件）时路径可能已被其自行清理。
        if spool_path:
            try:
                os.unlink(spool_path)
            except OSError:
                pass

    if result["status"] == "remounted":
        if result["replaced"] is None:
            flash("相同内容的诊断包已在库，已直接挂到事件 {}（不重复占用留存）".format(
                event_no), "ok")
        else:
            flash("相同内容的诊断包已在库，事件 {} 的附件已替换为该包".format(
                event_no), "ok")
    else:
        flash("诊断包 {}（{}）已入库并挂到事件 {}".format(
            result["filename"], packages.human_size(result["size_bytes"]),
            event_no), "ok")
    for b in result["evicted"]:
        flash("留存空间不足，按最早入库顺序清退诊断包 #{}（{}，{}），"
              "并移除其在事件 {} 上的挂载".format(
                  b["id"], b["filename"], packages.human_size(b["size_bytes"]),
                  "、".join(str(x) for x in b["events"]) or "无"), "error")
    return redirect(url_for(".event_packages", event_no=event_no))


@bp.route("/events/<int:event_no>/packages/download")
def download_package(event_no):
    db = get_db()
    if db.execute("SELECT 1 FROM events WHERE event_no = ?",
                  (event_no,)).fetchone() is None:
        abort(404)
    att = packages.event_attachment(db, event_no)
    if att is None:
        flash("事件 {} 当前没有挂载诊断包".format(event_no), "error")
        return redirect(url_for(".event_packages", event_no=event_no))
    if db.execute("SELECT 1 FROM blobs WHERE id = ?",
                  (att["blob_id"],)).fetchone() is None:  # 外键兜底
        flash("诊断包数据已不存在", "error")
        return redirect(url_for(".event_packages", event_no=event_no))
    try:
        stream, size = packages.open_blob_stream(
            current_app.config["DATABASE"], att["blob_id"])
    except packages.PackageError:
        flash("诊断包数据已不存在", "error")
        return redirect(url_for(".event_packages", event_no=event_no))
    # RFC 6266：中文文件名走 filename*=UTF-8''，ASCII 名走 filename。
    resp = Response(
        stream, mimetype=att["content_type"] or "application/octet-stream")
    resp.headers["Content-Length"] = size
    resp.headers["X-Blob-Digest"] = att["digest"]
    resp.headers["Content-Disposition"] = (
        "attachment; filename=\"{ascii}\"; filename*=UTF-8''{utf8}").format(
        ascii=secure_filename(att["filename"]) or "package.bin",
        utf8=url_quote(att["filename"]))
    return resp

