import os
import sqlite3
import json
from contextlib import contextmanager
from typing import Optional, Tuple, Dict, Any, Generator
from config import DB_PATH
from canonical import canonical, now_iso

def _connect_and_setup(target_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(target_path, timeout=30.0)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=15000;")
        return conn
    except Exception:
        conn.close()
        raise

@contextmanager
def get_db(path: Optional[str] = None) -> Generator[sqlite3.Connection, None, None]:
    target_path = path or DB_PATH
    try:
        conn = _connect_and_setup(target_path)
    except sqlite3.DatabaseError:
        # Self-healing: if an existing sqlite file from git clone is malformed, recreate cleanly
        try:
            if os.path.exists(target_path):
                os.remove(target_path)
            for ext in ("-shm", "-wal"):
                sidecar = target_path + ext
                if os.path.exists(sidecar):
                    os.remove(sidecar)
        except Exception:
            pass
        conn = _connect_and_setup(target_path)

    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db(path: Optional[str] = None):
    with get_db(path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                state_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                run_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                PRIMARY KEY (run_id, receipt_id)
            )
        """)

def get_run(run_id: str, path: Optional[str] = None) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Returns (request_hash, state_dict) or None if not found."""
    with get_db(path) as conn:
        row = conn.execute(
            "SELECT request_hash, state_json FROM runs WHERE run_id=?",
            (run_id,)
        ).fetchone()
        if not row:
            return None
        return row["request_hash"], json.loads(row["state_json"])

def save_run(run_id: str, request_hash: str, state: Dict[str, Any], path: Optional[str] = None):
    """Inserts a new run record."""
    timestamp = now_iso()
    with get_db(path) as conn:
        conn.execute(
            "INSERT INTO runs(run_id, request_hash, state_json, created_at) VALUES(?, ?, ?, ?)",
            (run_id, request_hash, canonical(state), timestamp)
        )

def update_run(run_id: str, state: Dict[str, Any], path: Optional[str] = None):
    """Updates an existing run record state."""
    with get_db(path) as conn:
        conn.execute(
            "UPDATE runs SET state_json=? WHERE run_id=?",
            (canonical(state), run_id)
        )

def get_receipt(run_id: str, receipt_id: str, path: Optional[str] = None) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Returns (request_hash, response_dict) or None if not found."""
    with get_db(path) as conn:
        row = conn.execute(
            "SELECT request_hash, response_json FROM receipts WHERE run_id=? AND receipt_id=?",
            (run_id, receipt_id)
        ).fetchone()
        if not row:
            return None
        return row["request_hash"], json.loads(row["response_json"])

def save_receipt(run_id: str, receipt_id: str, request_hash: str, response: Dict[str, Any], path: Optional[str] = None):
    """Saves a receipt record."""
    with get_db(path) as conn:
        conn.execute(
            "INSERT INTO receipts(run_id, receipt_id, request_hash, response_json) VALUES(?, ?, ?, ?)",
            (run_id, receipt_id, request_hash, canonical(response))
        )
