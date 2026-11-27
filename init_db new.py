"""Create the Ransomware Rescue SQLite database.

Usage:
    python init_db.py                 # create empty database from schema.sql
    python init_db.py --seed          # also add synthetic demo data
    python init_db.py --reset --seed  # delete old DB first (demo data only!)

The seed data matches schema.sql exactly (documents, versions, findings,
controls, tests...). Every hash is computed from real synthetic content, and
every timestamp is a valid ISO-8601 value. No passwords or key material.
"""
import argparse
import hashlib
import sqlite3
from pathlib import Path

HERE = Path(__file__).parent


def connect(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")  # SQLite needs this on EVERY connection
    return conn


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seed(conn):
    q = conn.executemany

    q("INSERT INTO team_roles (role_id, role_name, responsibility, evidence_expected, member_name) VALUES (?,?,?,?,?)", [
        (1, "Security Architect", "Map assets, data flows, threats and release criteria.", "Architecture/data-flow diagram and risk list.", "Student A"),
        (2, "Cloud Security Engineer", "Verify service setup, identities and supported operations.", "Setup notes and service checks.", "Student B"),
        (3, "Application Security Engineer", "Implement the defensive workflow and remediation.", "Code/change summary and test references.", "Student C"),
        (4, "Identity & Data Security Engineer", "Review access, data minimisation and secret/key handling.", "Permission matrix and data-flow notes.", "Student D"),
        (5, "Detection, Testing & Evidence Engineer", "Design tests, inspect logs and assemble evidence.", "Test matrix, redacted logs and report appendix.", "Student E"),
    ])

    q("INSERT INTO assets (asset_id, name, asset_type, trust_boundary, sensitivity, description) VALUES (?,?,?,?,?,?)", [
        (1, "Student vault documents", "document", "Application / Cloud Storage", "High", "Synthetic student records held in the protected vault."),
        (2, "Cloud Storage bucket", "data_store", "Cloud Storage", "High", "Versioned object store holding document copies."),
        (3, "Encryption key (KMS)", "key", "Cloud KMS", "High", "Key used to encrypt vault objects (metadata only)."),
        (4, "Security event log", "log", "Cloud Logging", "Medium", "Sanitised record of detection and recovery events."),
        (5, "Demo API", "service", "Application", "Medium", "Minimal workflow exposing record/verify/recover operations."),
    ])

    q("INSERT INTO threats (threat_id, asset_id, stride_category, description, likelihood, impact) VALUES (?,?,?,?,?,?)", [
        (1, 1, "Tampering", "Ransomware-style modification silently alters vault documents.", "Medium", "High"),
        (2, 2, "Tampering", "Object overwritten with no version to recover from.", "Low", "High"),
        (3, 3, "Info disclosure", "Key material exposed in code, logs or screenshots.", "Low", "High"),
        (4, 4, "Repudiation", "Detection/recovery not logged, so incident cannot be traced.", "Medium", "Medium"),
        (5, 1, "Info disclosure", "Real/sensitive data used instead of synthetic records.", "Low", "High"),
    ])

    conn.execute(
        "INSERT INTO kms_keys (key_id, key_alias, purpose, algorithm, managed_by, rotation_assumption, created_at) "
        "VALUES (1,'vault-key-01','Encrypt vault document objects','AES-256 (envelope)','Cloud KMS (simulated)',"
        "'90-day rotation assumed; not verified in lab.','2026-11-10T09:00:00')")

    # Synthetic documents. Hashes are computed from the content below.
    docs = {
        1: ("enrolment_record_1001.txt", "SYN-1001", b"Synthetic enrolment record. ID: SYN-1001. Status: Active.\n"),
        2: ("transcript_1002.txt", "SYN-1002", b"Synthetic transcript. ID: SYN-1002. Result: Pass.\n"),
        3: ("fees_statement_1003.txt", "SYN-1003", b"Synthetic fees statement. ID: SYN-1003. Paid: Yes.\n"),
    }
    for did, (name, owner, _) in docs.items():
        conn.execute(
            "INSERT INTO documents (document_id, doc_name, doc_owner, classification, current_version_id, status, created_at) "
            "VALUES (?,?,?,?,NULL,'healthy','2026-11-10T09:00:00')", (did, name, owner, "Synthetic-Internal"))

    # version_id 1-3 = v1 of each doc (known good); version_id 4 = tampered v2 of doc 2
    tampered = docs[2][2] + b"[ENCRYPTED_BY_SIM_RANSOMWARE]\n"
    versions = [(vid, did, 1, docs[did][2], 1) for vid, did in ((1, 1), (2, 2), (3, 3))]
    for vid, did, vno, content, good in versions:
        conn.execute(
            "INSERT INTO document_versions (version_id, document_id, version_no, sha256_hash, size_bytes, encrypted, "
            "kms_key_id, storage_ref, is_known_good, created_at) VALUES (?,?,?,?,?,1,1,?,?,'2026-11-10T09:00:00')",
            (vid, did, vno, sha256(content), len(content), f"gs://vault-sandbox/{docs[did][0]}#v{vno}", good))
    conn.execute(
        "INSERT INTO document_versions (version_id, document_id, version_no, sha256_hash, size_bytes, encrypted, "
        "kms_key_id, storage_ref, is_known_good, created_at) VALUES (4,2,2,?,?,0,1,?,0,'2026-11-12T14:00:00')",
        (sha256(tampered), len(tampered), f"gs://vault-sandbox/{docs[2][0]}#v2"))
    for vid, did in ((1, 1), (2, 2), (3, 3)):
        conn.execute("UPDATE documents SET current_version_id=? WHERE document_id=?", (vid, did))
    conn.execute("UPDATE documents SET status='recovered' WHERE document_id=2")

    good2, bad2 = sha256(docs[2][2]), sha256(tampered)
    q("INSERT INTO integrity_checks (check_id, document_id, version_id, expected_hash, observed_hash, result, checked_at, note) VALUES (?,?,?,?,?,?,?,?)", [
        (1, 2, 4, good2, bad2, "mismatch", "2026-11-12T15:00:00", "Current version hash does not match recorded baseline."),
        (2, 2, 2, good2, good2, "match", "2026-11-12T15:40:00", "Recovered copy matches recorded known-good hash."),
    ])

    conn.execute(
        "INSERT INTO incidents (incident_id, document_id, title, detected_at, detection_method, severity, status, summary) "
        "VALUES (1,2,'Simulated ransomware modification of transcript_1002','2026-11-12T15:00:00','SHA-256 hash mismatch','High','recovered',"
        "'A copy of transcript_1002 was altered with a benign marker. Integrity check flagged it; known-good version restored and verified.')")
    conn.execute(
        "INSERT INTO recovery_events (recovery_id, incident_id, document_id, restored_version_id, hash_verified, recovered_at, outcome) "
        "VALUES (1,1,2,2,1,'2026-11-12T15:40:00','Known-good version restored and hash verified.')")

    q("INSERT INTO security_events (event_id, event_type, occurred_at, outcome, correlation_id, document_id, actor, severity, message) VALUES (?,?,?,?,?,?,?,?,?)", [
        (1, "HASH_RECORDED", "2026-11-11T10:00:00", "success", "corr-rec-1", 1, "Student E", "Informational", "Baseline SHA-256 recorded for vault document."),
        (2, "HASH_RECORDED", "2026-11-11T10:00:00", "success", "corr-rec-2", 2, "Student E", "Informational", "Baseline SHA-256 recorded for vault document."),
        (3, "HASH_RECORDED", "2026-11-11T10:00:00", "success", "corr-rec-3", 3, "Student E", "Informational", "Baseline SHA-256 recorded for vault document."),
        (4, "INTEGRITY_FAIL", "2026-11-12T15:00:00", "blocked", "corr-inc-2", 2, "system", "High", "Integrity comparison failed - document flagged as modified."),
        (5, "RECOVERY", "2026-11-12T15:40:00", "success", "corr-inc-2", 2, "Student C", "High", "Document restored from known-good version; hash verified."),
        (6, "ERROR", "2026-11-12T15:50:00", "failure", "corr-err-1", None, "system", "Low", "Unexpected input rejected safely; no sensitive data logged."),
    ])

    q("INSERT INTO findings (finding_id, title, description, severity, asset_id, impact, remediation, status, retest_result, evidence_filename, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)", [
        ("F01", "No integrity baseline for vault documents", "Documents had no recorded hash, so modification could not be detected.", "High", 1, "Ransomware-style change would go unnoticed.", "Record SHA-256 at ingest and verify on access.", "remediated", "Pass after fix (T01/T02)", "TC-T02-after.png", "2026-11-11T11:30:00"),
        ("F02", "No versioned recovery path", "Only a single copy existed; no known-good version to restore.", "High", 2, "Unrecoverable data loss after modification.", "Keep versioned copies; mark a known-good version.", "remediated", "Pass after fix (T03)", "TC-T03-after.png", "2026-11-11T11:40:00"),
        ("F03", "Detection and recovery not logged", "Security-relevant actions were not recorded.", "Medium", 4, "Incident cannot be traced or evidenced.", "Add sanitised event logging for all key actions.", "remediated", "Pass after fix (T05)", "TC-T05-after.png", "2026-11-11T11:45:00"),
        ("F04", "Key handling not documented", "Key purpose/rotation assumptions were undocumented.", "Low", 3, "Unclear control boundary for encryption.", "Record key metadata and assumptions; store no material.", "accepted", "Documented as limitation", "", "2026-11-12T00:00:00"),
    ])

    q("INSERT INTO controls (control_id, name, control_type, description, risk_addressed, finding_id, status) VALUES (?,?,?,?,?,?,?)", [
        (1, "SHA-256 integrity baseline", "integrity", "Record and compare document hashes to detect tampering.", "Undetected modification", "F01", "verified"),
        (2, "Versioned known-good recovery", "recovery", "Retain versioned copies and restore a verified known-good version.", "Unrecoverable data loss", "F02", "verified"),
        (3, "Encryption at rest (KMS)", "encryption", "Encrypt vault objects; store key metadata only.", "Key/data exposure", "F04", "implemented"),
        (4, "Sanitised security logging", "logging", "Log detection and recovery without secrets or payloads.", "Untraceable incident", "F03", "verified"),
        (5, "Synthetic-data + scoped access", "access", "Use synthetic records only within the assigned sandbox.", "Sensitive data exposure", None, "implemented"),
    ])

    q("INSERT INTO test_cases (test_id, title, expected_result, evidence_type) VALUES (?,?,?,?)", [
        ("T01", "Original file hash is recorded before modification.", "Baseline hash stored; unsafe action prevented.", "Screenshot, test output or redacted log."),
        ("T02", "Benign change causes integrity comparison to fail.", "Mismatch detected and flagged.", "Screenshot, test output or redacted log."),
        ("T03", "Recovery copy matches the known-good hash.", "Restored hash matches baseline.", "Screenshot, test output or redacted log."),
        ("T04", "Only designated test data is changed.", "No non-test data modified.", "Screenshot, test output or redacted log."),
        ("T05", "Logs document detection and recovery.", "Events present and traceable.", "Screenshot, test output or redacted log."),
        ("T06", "Trigger a controlled unexpected error.", "Safe response; useful event recorded.", "Redacted log excerpt."),
        ("T07", "Inspect source, output and logs for sensitive data.", "No secret or unnecessary data exposed.", "Sanitised search output."),
        ("T08", "Repeat the complete test set.", "Reproducible; limitations documented.", "Completed matrix."),
    ])

    q("INSERT INTO test_runs (test_id, phase, input_event, expected_result, observed_result, pass_fail, evidence_filename, run_at, run_by) VALUES (?,?,?,?,?,?,?,?,?)", [
        ("T01", "baseline", "Record hash of doc", "Hash stored", "No baseline hash captured", "fail", "TC-T01-baseline.png", "2026-11-11T11:30:00", "Student E"),
        ("T02", "baseline", "Modify copy of doc 2", "Mismatch detected", "Change went undetected", "fail", "TC-T02-baseline.png", "2026-11-11T11:35:00", "Student E"),
        ("T03", "baseline", "Restore doc 2", "Hash matches", "No known-good version available", "fail", "TC-T03-baseline.png", "2026-11-11T11:40:00", "Student E"),
        ("T05", "baseline", "Check logs", "Events present", "No security events logged", "fail", "TC-T05-baseline.png", "2026-11-11T11:45:00", "Student E"),
        ("T01", "after_fix", "Record hash of doc", "Hash stored", "Baseline hash recorded for all docs", "pass", "TC-T01-after.png", "2026-11-12T10:00:00", "Student E"),
        ("T02", "after_fix", "Modify copy of doc 2", "Mismatch detected", "Integrity check flagged mismatch", "pass", "TC-T02-after.png", "2026-11-12T16:00:00", "Student E"),
        ("T03", "after_fix", "Restore doc 2", "Hash matches", "Recovered hash matched baseline", "pass", "TC-T03-after.png", "2026-11-12T15:41:00", "Student E"),
        ("T04", "after_fix", "Change only test data", "Only test doc changed", "Confirmed only doc 2 copy altered", "pass", "TC-T04-after.png", "2026-11-12T20:00:00", "Student E"),
        ("T05", "after_fix", "Check logs", "Events present", "Detection + recovery events traceable", "pass", "TC-T05-after.png", "2026-11-12T15:45:00", "Student E"),
        ("T06", "after_fix", "Trigger bad input", "Safe error + event", "Input rejected safely, event logged", "pass", "TC-T06-after.png", "2026-11-12T15:51:00", "Student E"),
        ("T07", "after_fix", "Scan for secrets", "No secrets exposed", "No key material or PII found", "pass", "TC-T07-after.txt", "2026-11-12T15:55:00", "Student D"),
        ("T08", "after_fix", "Repeat full set", "Reproducible", "All after-fix tests reproduced", "pass", "TC-T08-matrix.png", "2026-11-13T00:00:00", "Student E"),
    ])

    q("INSERT INTO evidence (evidence_id, filename, evidence_type, description, related_test_id, related_finding_id, captured_at, captured_by) VALUES (?,?,?,?,?,?,?,?)", [
        (1, "TC-T01-after.png", "screenshot", "Baseline hash recorded for all documents.", "T01", None, "2026-11-12T10:00:00", "Student E"),
        (2, "TC-T02-after.png", "screenshot", "Integrity mismatch detected on modified copy.", "T02", "F01", "2026-11-12T16:00:00", "Student E"),
        (3, "TC-T03-after.png", "screenshot", "Recovered document hash matches baseline.", "T03", "F02", "2026-11-12T15:41:00", "Student E"),
        (4, "TC-T05-after.png", "log", "Detection and recovery events in log.", "T05", "F03", "2026-11-12T15:45:00", "Student E"),
        (5, "TC-T07-after.txt", "test_output", "Secret/PII scan output - clean.", "T07", None, "2026-11-12T15:55:00", "Student D"),
        (6, "security-assessment-report.pdf", "report", "Final security assessment report.", None, None, "2026-11-13T00:30:00", "Team"),
    ])


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
