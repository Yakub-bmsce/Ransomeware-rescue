#!/usr/bin/env python3
"""
vault_guard.py  -  Ransomware Rescue demo app (Project 04)

A tiny command-line tool that sits on top of ransomware_rescue.db and
runs the defensive workflow on real files in a local ./vault folder:

  record   T01  store a document + its SHA-256 as the known-good baseline
  check    T02  re-hash the live file and compare to the baseline
  tamper        simulate a benign ransomware-style change (for the demo)
  recover  T03  restore the known-good copy and verify its hash
  log      T05  show the sanitised security event log
  status        show each document's health
  demo          run the whole story end to end on a sample file

SAFETY: synthetic/sample files only. 'tamper' makes a harmless, reversible
text change to a file YOU created in ./vault. No real systems are touched,
and no secrets or key material are ever stored or printed.

Usage:
  python vault_guard.py demo
  python vault_guard.py record vault/myfile.txt
  python vault_guard.py check  vault/myfile.txt
  python vault_guard.py --db ransomware_rescue.db log
"""
import argparse, sqlite3, hashlib, os, shutil, uuid, sys
from datetime import datetime

VAULT = "vault"
BACKUP = os.path.join(VAULT, ".known_good")   # hidden store of good copies

# ---------- helpers ----------
def now():
    return datetime.now().isoformat(timespec="seconds")

def corr():
    return "corr-" + uuid.uuid4().hex[:8]

def sha256_file(path):
    hsh = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hsh.update(chunk)
    return hsh.hexdigest()

def connect(db):
    if not os.path.exists(db):
        sys.exit(f"Database not found: {db}  (create it with: python init_db.py --seed)")
    con = sqlite3.connect(db)
    con.execute("PRAGMA foreign_keys = ON")
    con.row_factory = sqlite3.Row
    return con

def log_event(con, event_type, outcome, severity, message, document_id=None,
              actor="vault_guard", correlation_id=None):
    con.execute("""INSERT INTO security_events
        (event_type,occurred_at,outcome,correlation_id,document_id,actor,severity,message)
        VALUES (?,?,?,?,?,?,?,?)""",
        (event_type, now(), outcome, correlation_id or corr(),
         document_id, actor, severity, message))

def fail(con, reason, document_id=None):
    """T06: reject safely, record a sanitised ERROR event, then exit.
    The logged message is a fixed reason - never the user's path or content."""
    log_event(con, "ERROR", "failure", "Low",
              f"Request rejected safely: {reason}.", document_id)
    con.commit()
    sys.exit(f"Error: {reason}.")

def get_doc(con, name):
    return con.execute("SELECT * FROM documents WHERE doc_name=?", (name,)).fetchone()

def known_good(con, document_id):
    return con.execute("""SELECT * FROM document_versions
        WHERE document_id=? AND is_known_good=1""", (document_id,)).fetchone()

def backup_path(document_id, version_no):
    return os.path.join(BACKUP, f"{document_id}_v{version_no}.bak")

# ---------- commands ----------
def cmd_record(con, path):
    if not os.path.isfile(path):
        fail(con, "file not found")
    os.makedirs(BACKUP, exist_ok=True)
    name = os.path.basename(path)
    digest = sha256_file(path)
    size = os.path.getsize(path)

    doc = get_doc(con, name)
    if doc is None:
        cur = con.execute("""INSERT INTO documents
            (doc_name,doc_owner,classification,status,created_at)
            VALUES (?,?,?,?,?)""",
            (name, "SYN-APP", "Synthetic-Internal", "healthy", now()))
        document_id = cur.lastrowid
        version_no = 1
    else:
        document_id = doc["document_id"]
        row = con.execute("""SELECT COALESCE(MAX(version_no),0) m
            FROM document_versions WHERE document_id=?""", (document_id,)).fetchone()
        version_no = row["m"] + 1
        # old versions are no longer the baseline
        con.execute("UPDATE document_versions SET is_known_good=0 WHERE document_id=?",
                    (document_id,))

    cur = con.execute("""INSERT INTO document_versions
        (document_id,version_no,sha256_hash,size_bytes,encrypted,kms_key_id,
         storage_ref,is_known_good,created_at)
        VALUES (?,?,?,?,0,NULL,?,1,?)""",
        (document_id, version_no, digest, size, os.path.abspath(path), now()))
    version_id = cur.lastrowid
    con.execute("UPDATE documents SET current_version_id=?, status='healthy' WHERE document_id=?",
                (version_id, document_id))
    shutil.copy2(path, backup_path(document_id, version_no))
    log_event(con, "HASH_RECORDED", "success", "Informational",
              "Baseline SHA-256 recorded for vault document.", document_id)
    con.commit()
    print(f"[T01] recorded '{name}'  (v{version_no})")
    print(f"      sha256 = {digest}")
    print(f"      known-good baseline saved. status = healthy")

def cmd_check(con, path):
    name = os.path.basename(path)
    doc = get_doc(con, name)
    if doc is None:
        fail(con, "document has not been recorded")
    if not os.path.isfile(path):
        fail(con, "live file missing", doc["document_id"])
    kg = known_good(con, doc["document_id"])
    observed = sha256_file(path)
    expected = kg["sha256_hash"]
    result = "match" if observed == expected else "mismatch"

    con.execute("""INSERT INTO integrity_checks
        (document_id,version_id,expected_hash,observed_hash,result,checked_at,note)
        VALUES (?,?,?,?,?,?,?)""",
        (doc["document_id"], kg["version_id"], expected, observed, result, now(),
         "Live file compared to recorded known-good baseline."))

    if result == "match":
        log_event(con, "INTEGRITY_OK", "success", "Informational",
                  "Integrity check passed - file matches baseline.", doc["document_id"])
        con.commit()
        print(f"[OK]  '{name}' integrity verified. hash matches baseline.")
    else:
        cid = corr()
        log_event(con, "INTEGRITY_FAIL", "blocked", "High",
                  "Integrity comparison failed - document flagged as modified.",
                  doc["document_id"], correlation_id=cid)
        con.execute("UPDATE documents SET status='compromised' WHERE document_id=?",
                    (doc["document_id"],))
        # open an incident if one isn't already active
        open_inc = con.execute("""SELECT incident_id FROM incidents
            WHERE document_id=? AND status IN ('detected','contained')""",
            (doc["document_id"],)).fetchone()
        if open_inc is None:
            con.execute("""INSERT INTO incidents
                (document_id,title,detected_at,detection_method,severity,status,summary)
                VALUES (?,?,?,?,?,?,?)""",
                (doc["document_id"], f"Modification detected on {name}", now(),
                 "SHA-256 hash mismatch", "High", "detected",
                 "Live file hash does not match recorded baseline."))
        con.commit()
        print(f"[T02] [ALERT] '{name}' has been MODIFIED.")
        print(f"      expected {expected[:16]}...  got {observed[:16]}...")
        print(f"      incident raised. status = compromised. run: recover {path}")

def cmd_tamper(con, path):
    if not os.path.isfile(path):
        fail(con, "file not found")
    with open(path, "a") as f:
        f.write("\n[ENCRYPTED_BY_SIM_RANSOMWARE]\n")
    print(f"[sim] benign change written to '{os.path.basename(path)}' (reversible).")
    print(f"      this stands in for a ransomware modification. run: check {path}")

def cmd_recover(con, path):
    name = os.path.basename(path)
    doc = get_doc(con, name)
    if doc is None:
        fail(con, "document has not been recorded")
    kg = known_good(con, doc["document_id"])
    bkp = backup_path(doc["document_id"], kg["version_no"])
    if not os.path.isfile(bkp):
        fail(con, "known-good copy missing", doc["document_id"])
    shutil.copy2(bkp, path)
    observed = sha256_file(path)
    verified = int(observed == kg["sha256_hash"])

    con.execute("""INSERT INTO integrity_checks
        (document_id,version_id,expected_hash,observed_hash,result,checked_at,note)
        VALUES (?,?,?,?,?,?,?)""",
        (doc["document_id"], kg["version_id"], kg["sha256_hash"], observed,
         "match" if verified else "mismatch", now(),
         "Post-recovery verification against known-good baseline."))

    inc = con.execute("""SELECT incident_id FROM incidents
        WHERE document_id=? AND status IN ('detected','contained')
        ORDER BY incident_id DESC LIMIT 1""", (doc["document_id"],)).fetchone()
    inc_id = inc["incident_id"] if inc else None
    con.execute("""INSERT INTO recovery_events
        (incident_id,document_id,restored_version_id,hash_verified,recovered_at,outcome)
        VALUES (?,?,?,?,?,?)""",
        (inc_id, doc["document_id"], kg["version_id"], verified, now(),
         "Known-good version restored and hash verified." if verified
         else "Restore completed but hash did NOT verify."))
    if inc_id:
        con.execute("UPDATE incidents SET status='recovered' WHERE incident_id=?", (inc_id,))
    con.execute("UPDATE documents SET current_version_id=?, status='recovered' WHERE document_id=?",
                (kg["version_id"], doc["document_id"]))
    log_event(con, "RECOVERY", "success" if verified else "failure",
              "High", "Document restored from known-good version; hash verified."
              if verified else "Recovery hash verification FAILED.", doc["document_id"])
    con.commit()
    if verified:
        print(f"[T03] recovered '{name}'. hash verified against baseline.")
        print(f"      status = recovered. OK")
    else:
        print(f"[T03] [WARN] '{name}' restored but hash did not verify.")

def cmd_log(con, n):
    rows = con.execute("""SELECT occurred_at,event_type,outcome,severity,message
        FROM security_events ORDER BY event_id DESC LIMIT ?""", (n,)).fetchall()
    print(f"--- last {len(rows)} security events (newest first) ---")
    for r in rows:
        print(f"{r['occurred_at']}  {r['event_type']:<15} {r['outcome']:<8} "
              f"{r['severity']:<13} {r['message']}")

def cmd_status(con):
    rows = con.execute("""SELECT doc_name,status,current_version,integrity_ok
        FROM v_document_status ORDER BY doc_name""").fetchall()
    print(f"{'document':<32}{'status':<13}{'ver':<5}{'integrity'}")
    print("-" * 62)
    for r in rows:
        ok = "ok" if r["integrity_ok"] == 1 else ("-" if r["integrity_ok"] is None else "FAIL")
        print(f"{r['doc_name']:<32}{r['status']:<13}v{str(r['current_version'] or '-'):<4}{ok}")

def cmd_demo(con):
    os.makedirs(VAULT, exist_ok=True)
    sample = os.path.join(VAULT, "demo_record.txt")
    with open(sample, "w") as f:
        f.write("Synthetic student record. Name: Test User. ID: SYN-DEMO. Grade: A.\n")
    print("=== Ransomware Rescue demo ===\n")
    print("1) record baseline");           cmd_record(con, sample); print()
    print("2) check (healthy)");            cmd_check(con, sample);  print()
    print("3) simulate ransomware");        cmd_tamper(con, sample); print()
    print("4) check (detects change)");     cmd_check(con, sample);  print()
    print("5) recover + verify");           cmd_recover(con, sample);print()
    print("6) check (healthy again)");      cmd_check(con, sample);  print()
    print("7) event log");                  cmd_log(con, 6);         print()
    print("=== done ===")

# ---------- entry ----------
def main():
    p = argparse.ArgumentParser(description="Ransomware Rescue demo app")
    p.add_argument("--db", default="ransomware_rescue.db", help="path to the SQLite database")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("record", "check", "tamper", "recover"):
        s = sub.add_parser(name); s.add_argument("file")
    sub.add_parser("status")
    sub.add_parser("demo")
    lg = sub.add_parser("log"); lg.add_argument("-n", type=int, default=12)

    args = p.parse_args()
    con = connect(args.db)
    try:
        if   args.cmd == "record":  cmd_record(con, args.file)
        elif args.cmd == "check":   cmd_check(con, args.file)
        elif args.cmd == "tamper":  cmd_tamper(con, args.file)
        elif args.cmd == "recover": cmd_recover(con, args.file)
        elif args.cmd == "status":  cmd_status(con)
        elif args.cmd == "log":     cmd_log(con, args.n)
        elif args.cmd == "demo":    cmd_demo(con)
    finally:
        con.close()

if __name__ == "__main__":
    main()
