"""SQLite-backed job queue shared by the bot and the runner."""
import sqlite3, time
from config import DB_PATH

SCHEMA = """CREATE TABLE IF NOT EXISTS jobs(
    id TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    platform TEXT NOT NULL,
    notes TEXT DEFAULT '',
    status TEXT DEFAULT 'queued',
    action TEXT DEFAULT '',
    flags TEXT DEFAULT '[]',
    created INTEGER,
    updated INTEGER
)"""


def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    with db() as c:
        c.execute(SCHEMA)


def create(job_id, ip, platform, notes=""):
    job_id = job_id.strip().lower()
    now = int(time.time())
    with db() as c:
        c.execute(
            "INSERT INTO jobs (id,ip,platform,notes,status,created,updated)"
            " VALUES (?,?,?,?,?,?,?)",
            (job_id, ip, platform, notes, "queued", now, now),
        )


def get(job_id):
    job_id = job_id.strip().lower()
    with db() as c:
        row = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    return dict(row) if row else None


def update(job_id, **fields):
    job_id = job_id.strip().lower()
    fields["updated"] = int(time.time())
    sets = ", ".join(f"{k}=?" for k in fields)
    with db() as c:
        c.execute(f"UPDATE jobs SET {sets} WHERE id=?",
                  (*fields.values(), job_id))


def next_queued():
    with db() as c:
        row = c.execute(
            "SELECT * FROM jobs WHERE status='queued'"
            " ORDER BY created LIMIT 1").fetchone()
    return dict(row) if row else None


def recent(limit=10):
    with db() as c:
        rows = c.execute(
            "SELECT id,ip,platform,status,created FROM jobs"
            " ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]
