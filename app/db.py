"""SQLite 连接与建表。"""
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_no     INTEGER PRIMARY KEY,
    boot_id    TEXT NOT NULL,
    pid        INTEGER NOT NULL,
    cgroup     TEXT NOT NULL,
    start_ms   INTEGER NOT NULL,
    end_ms     INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_match
    ON runs(boot_id, pid, cgroup, start_ms, end_ms);

CREATE TABLE IF NOT EXISTS events (
    event_no   INTEGER PRIMARY KEY,
    boot_id    TEXT NOT NULL,
    pid        INTEGER NOT NULL,
    cgroup     TEXT NOT NULL,
    time_ms    INTEGER NOT NULL,
    scope      TEXT NOT NULL CHECK (scope IN ('memcg', 'host')),
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attributions (
    event_no    INTEGER PRIMARY KEY REFERENCES events(event_no) ON DELETE CASCADE,
    status      TEXT NOT NULL CHECK (status IN ('unique', 'pending')),
    run_no      INTEGER,
    match_count INTEGER NOT NULL,
    fingerprint TEXT,
    computed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS confirmations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_no      INTEGER NOT NULL REFERENCES events(event_no) ON DELETE CASCADE,
    run_no        INTEGER NOT NULL,
    scope         TEXT NOT NULL,
    fingerprint   TEXT NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    confirmed_at  TEXT NOT NULL,
    revoked_at    TEXT,
    revoke_reason TEXT
);
-- 同一事件至多一条有效确认（并发下也由数据库保证）。
CREATE UNIQUE INDEX IF NOT EXISTS uq_conf_active
    ON confirmations(event_no) WHERE state = 'active';
CREATE INDEX IF NOT EXISTS idx_conf_event ON confirmations(event_no, state);

-- 现场诊断包：内容寻址，同一 sha256 只存一份字节（跨事件共用不重复计字节）。
CREATE TABLE IF NOT EXISTS blobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,  -- 自增顺序即首次入库顺序
    digest       TEXT NOT NULL UNIQUE,               -- sha256 十六进制摘要
    size_bytes   INTEGER NOT NULL CHECK (size_bytes > 0),
    filename     TEXT NOT NULL,
    content_type TEXT,
    data         BLOB NOT NULL,
    ingested_at  TEXT NOT NULL
);

-- 事件挂载：每个事件至多一个附件（event_no 主键），同一个包可挂多个事件。
-- 删除 blob 时级联移除其全部挂载；删除事件时级联移除其挂载。
CREATE TABLE IF NOT EXISTS event_attachments (
    event_no   INTEGER PRIMARY KEY REFERENCES events(event_no) ON DELETE CASCADE,
    blob_id    INTEGER NOT NULL REFERENCES blobs(id) ON DELETE CASCADE,
    mounted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ea_blob ON event_attachments(blob_id);
"""


def connect(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_schema(conn):
    conn.executescript(SCHEMA)
