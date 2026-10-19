"""SQLite persistence. Only redacted findings and document metadata are saved."""
import json
import sqlite3
import threading
from pathlib import Path


class Store:
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.lock = threading.RLock()
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS schedules (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL);
        """)
        self.db.commit()

    def save_run(self, run):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?)", (run["id"], run["created_at"], json.dumps(run, ensure_ascii=False)))

    def get_run(self, run_id):
        with self.lock:
            row = self.db.execute("SELECT payload FROM runs WHERE id=?", (run_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list_runs(self, limit=100):
        with self.lock:
            rows = self.db.execute("SELECT payload FROM runs ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,)).fetchall()
        keys = ("id", "target", "mode", "variant", "status", "created_at", "summary", "baseline_id", "coverage")
        return [{k: run.get(k) for k in keys} for run in (json.loads(r[0]) for r in rows)]

    def save_schedule(self, item):
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO schedules VALUES (?,?)", (item["id"], json.dumps(item, ensure_ascii=False)))

    def schedules(self):
        with self.lock:
            rows = self.db.execute("SELECT payload FROM schedules ORDER BY rowid DESC").fetchall()
        return [json.loads(r[0]) for r in rows]

    def add_event(self, item):
        with self.lock, self.db:
            self.db.execute("INSERT INTO events(payload) VALUES (?)", (json.dumps(item, ensure_ascii=False),))

    def events(self, limit=100):
        with self.lock:
            rows = self.db.execute("SELECT id,payload FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(json.loads(r[1]), id=r[0]) for r in rows]

    def review(self, run_id, finding_id, status, note):
        with self.lock:
            run = self.get_run(run_id)
            if run is None:
                raise KeyError("任务不存在")
            for finding in run["findings"]:
                if finding["id"] == finding_id:
                    finding["review_status"] = status
                    finding["review_note"] = note
                    self.save_run(run)
                    return
            raise KeyError("发现不存在")

    def close(self):
        with self.lock:
            self.db.close()

