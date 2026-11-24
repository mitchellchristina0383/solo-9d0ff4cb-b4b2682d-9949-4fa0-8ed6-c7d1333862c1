"""OOM 归属核对应用：Flask 应用工厂。"""
import os

from flask import Flask, render_template

from .core import recompute_all
from .db import close_db, connect, init_schema
from .packages import cleanup_spool, parse_quota


def create_app(config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "oom-duty-dev-key"),
        DATABASE=os.environ.get(
            "OOM_DB", os.path.join(app.instance_path, "oom.db")
        ),
        # 现场诊断包留存上限（字节）。OOM_BLOB_QUOTA 支持 100M / 2g / 纯字节数。
        BLOB_QUOTA=parse_quota(os.environ.get("OOM_BLOB_QUOTA", "100M")),
        BLOB_SPOOL_DIR=os.environ.get(
            "OOM_BLOB_SPOOL",
            os.path.join(app.instance_path, "blob-spool")),
    )
    if config:
        app.config.from_mapping(config)
    # 允许测试直接传字节数
    if isinstance(app.config.get("BLOB_QUOTA"), str):
        app.config["BLOB_QUOTA"] = parse_quota(app.config["BLOB_QUOTA"])

    db_path = app.config["DATABASE"]
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)

    # 启动时建表并重核一次：保证重启后结论与确认状态和数据一致。
    conn = connect(db_path)
    try:
        init_schema(conn)
        recompute_all(conn)
        conn.commit()
    finally:
        conn.close()

    # 清理上次接收中断残留的临时文件；原附件都在 SQLite 内，不受影响。
    cleanup_spool(app.config["BLOB_SPOOL_DIR"])

    # 请求体超过留存上限没有任何入库可能，直接由 Flask 拒收（见 413 处理）。
    app.config["MAX_CONTENT_LENGTH"] = app.config["BLOB_QUOTA"]

    from .views import bp
    from .packages import human_size

    app.register_blueprint(bp)
    app.teardown_appcontext(close_db)
    app.jinja_env.filters["hsize"] = human_size

    @app.errorhandler(413)
    def too_large(e):
        return render_template(
            "error.html",
            message="上传文件超过留存上限（{}），服务器未接收；"
                    "请在「诊断包留存」中核对配额后重试。".format(
                        app.config["BLOB_QUOTA"])), 413

    return app
