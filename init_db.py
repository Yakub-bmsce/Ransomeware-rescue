"""Create the Ransomware Rescue SQLite database.

Usage:
    python init_db.py                 # create empty database
    python init_db.py --seed          # also add synthetic demo data
    python init_db.py --reset --seed  # delete old DB first (demo data only!)
"""
import argparse
import hashlib
import sqlite3
from pathlib import Path

import bcrypt

HERE = Path(__file__).parent
DEMO_PASSWORD = "DemoOnly#2026"  # synthetic lab password, never reuse anywhere real


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")  # SQLite needs this on EVERY connection
    return conn


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seed(conn):
    pw = bcrypt.hashpw(DEMO_PASSWORD.encode(), bcrypt.gensalt()).decode()
    conn.executemany(
        "INSERT INTO students (student_code, full_name, email, password_hash, role) VALUES (?,?,?,?,?)",
        [("S0001", "Demo Student One", "student1@example.test", pw, "student"),
         ("S0002", "Demo Student Two", "student2@example.test", pw, "student"),
         ("A0001", "Demo Admin", "admin@example.test", pw, "admin")],
    )
    content = b"synthetic notes v1"
    conn.execute(
        "INSERT INTO files (owner_id, filename, stored_path, size_bytes, sha256) VALUES (1,?,?,?,?)",
        ("notes.txt", "vault/S0001/notes.txt", len(content), sha256(content)),
    )
    conn.execute(
        "INSERT INTO backups (file_id, version_no, backup_path, sha256, size_bytes, integrity_status)"
        " VALUES (1,1,?,?,?,'verified')",
        ("backups/S0001/notes.txt.v1", sha256(content), len(content)),
    )
    conn.execute(
        "INSERT INTO audit_log (student_id, event_type, outcome, correlation_id) VALUES (1,'seed_data','success','seed-0001')"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(HERE / "ransomware_rescue.db"))
    ap.add_argument("--seed", action="store_true")
    ap.add_argument("--reset", action="store_true")
    args = ap.parse_args()

    db = Path(args.db)
    if args.reset and db.exists():
        db.unlink()
    conn = connect(db)
    conn.executescript((HERE / "schema.sql").read_text())
    if args.seed:
        seed(conn)
    conn.commit()
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    print(f"Created {db.name} with tables: {', '.join(tables)}")
    conn.close()


if __name__ == "__main__":
    main()
