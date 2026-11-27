CREATE TABLE assets (
    asset_id       INTEGER PRIMARY KEY,
    name           TEXT NOT NULL,
    asset_type     TEXT NOT NULL CHECK (asset_type IN
                       ('document','data_store','service','key','credential','log')),
    trust_boundary TEXT NOT NULL,
    sensitivity    TEXT NOT NULL CHECK (sensitivity IN ('Low','Medium','High')),
    description    TEXT
);
CREATE TABLE controls (
    control_id     INTEGER PRIMARY KEY,
    name           TEXT NOT NULL,
    control_type   TEXT CHECK (control_type IN
                      ('integrity','encryption','recovery','logging','access')),
    description    TEXT,
    risk_addressed TEXT,
    finding_id     TEXT REFERENCES findings(finding_id),
    status         TEXT CHECK (status IN ('planned','implemented','verified'))
);
CREATE TABLE document_versions (
    version_id    INTEGER PRIMARY KEY,
    document_id   INTEGER NOT NULL REFERENCES documents(document_id),
    version_no    INTEGER NOT NULL,
    sha256_hash   TEXT NOT NULL,
    size_bytes    INTEGER,
    encrypted     INTEGER NOT NULL DEFAULT 1 CHECK (encrypted IN (0,1)),
    kms_key_id    INTEGER REFERENCES kms_keys(key_id),
    storage_ref   TEXT,                 -- synthetic cloud object name
    is_known_good INTEGER NOT NULL DEFAULT 0 CHECK (is_known_good IN (0,1)),
    created_at    TEXT,
    UNIQUE (document_id, version_no)
);
CREATE TABLE documents (
    document_id        INTEGER PRIMARY KEY,
    doc_name           TEXT NOT NULL,
    doc_owner          TEXT,            -- synthetic student id
    classification     TEXT,
    current_version_id INTEGER,         -- FK set after versions exist
    status             TEXT NOT NULL DEFAULT 'healthy'
                           CHECK (status IN ('healthy','compromised','recovered')),
    created_at         TEXT
);
CREATE TABLE evidence (
    evidence_id        INTEGER PRIMARY KEY,
    filename           TEXT NOT NULL,
    evidence_type      TEXT CHECK (evidence_type IN ('screenshot','log','test_output','report')),
    description        TEXT,
    related_test_id    TEXT REFERENCES test_cases(test_id),
    related_finding_id TEXT REFERENCES findings(finding_id),
    captured_at        TEXT,
    captured_by        TEXT
);
CREATE TABLE findings (
    finding_id        TEXT PRIMARY KEY,  -- F01 ..
    title             TEXT NOT NULL,
    description       TEXT,
    severity          TEXT CHECK (severity IN ('High','Medium','Low','Informational')),
    asset_id          INTEGER REFERENCES assets(asset_id),
    impact            TEXT,
    remediation       TEXT,
    status            TEXT CHECK (status IN ('open','remediated','accepted','closed')),
    retest_result     TEXT,
    evidence_filename TEXT,
    created_at        TEXT
);
CREATE TABLE incidents (
    incident_id      INTEGER PRIMARY KEY,
    document_id      INTEGER REFERENCES documents(document_id),
    title            TEXT NOT NULL,
    detected_at      TEXT,
    detection_method TEXT,
    severity         TEXT CHECK (severity IN ('High','Medium','Low','Informational')),
    status           TEXT NOT NULL DEFAULT 'detected'
                         CHECK (status IN ('detected','contained','recovered','closed')),
    summary          TEXT
);
CREATE TABLE integrity_checks (
    check_id      INTEGER PRIMARY KEY,
    document_id   INTEGER NOT NULL REFERENCES documents(document_id),
    version_id    INTEGER REFERENCES document_versions(version_id),
    expected_hash TEXT NOT NULL,
    observed_hash TEXT NOT NULL,
    result        TEXT NOT NULL CHECK (result IN ('match','mismatch')),
    checked_at    TEXT,
    note          TEXT
);
CREATE TABLE kms_keys (
    key_id              INTEGER PRIMARY KEY,
    key_alias           TEXT NOT NULL,
    purpose             TEXT,
    algorithm           TEXT,           -- e.g. AES-256 envelope
    managed_by          TEXT,           -- e.g. Cloud KMS (simulated)
    rotation_assumption TEXT,
    created_at          TEXT,
    note                TEXT DEFAULT 'Metadata only - no key material stored'
);
CREATE TABLE recovery_events (
    recovery_id         INTEGER PRIMARY KEY,
    incident_id         INTEGER REFERENCES incidents(incident_id),
    document_id         INTEGER REFERENCES documents(document_id),
    restored_version_id INTEGER REFERENCES document_versions(version_id),
    hash_verified       INTEGER CHECK (hash_verified IN (0,1)),
    recovered_at        TEXT,
    outcome             TEXT
);
CREATE TABLE security_events (
    event_id       INTEGER PRIMARY KEY,
    event_type     TEXT NOT NULL,       -- HASH_RECORDED / INTEGRITY_FAIL / RECOVERY / ERROR / ACCESS
    occurred_at    TEXT,
    outcome        TEXT CHECK (outcome IN ('success','failure','blocked')),
    correlation_id TEXT,
    document_id    INTEGER REFERENCES documents(document_id),
    actor          TEXT,                -- synthetic
    severity       TEXT,
    message        TEXT                 -- sanitised, no sensitive values
);
CREATE TABLE team_roles (
    role_id            INTEGER PRIMARY KEY,
    role_name          TEXT NOT NULL,
    responsibility     TEXT NOT NULL,
    evidence_expected  TEXT NOT NULL,
    member_name        TEXT              -- synthetic
);
CREATE TABLE test_cases (
    test_id         TEXT PRIMARY KEY,    -- T01 .. T08
    title           TEXT NOT NULL,
    expected_result TEXT,
    evidence_type   TEXT
);
CREATE TABLE test_runs (
    run_id            INTEGER PRIMARY KEY,
    test_id           TEXT NOT NULL REFERENCES test_cases(test_id),
    phase             TEXT NOT NULL CHECK (phase IN ('baseline','after_fix')),
    input_event       TEXT,
    expected_result   TEXT,
    observed_result   TEXT,
    pass_fail         TEXT CHECK (pass_fail IN ('pass','fail','blocked','na')),
    evidence_filename TEXT,
    run_at            TEXT,
    run_by            TEXT
);
CREATE TABLE threats (
    threat_id        INTEGER PRIMARY KEY,
    asset_id         INTEGER REFERENCES assets(asset_id),
    stride_category  TEXT,              -- Tampering / Info disclosure / etc
    description      TEXT NOT NULL,
    likelihood       TEXT CHECK (likelihood IN ('Low','Medium','High')),
    impact           TEXT CHECK (impact IN ('Low','Medium','High'))
);
CREATE VIEW v_document_status AS
SELECT d.document_id, d.doc_name, d.status,
       cv.version_no      AS current_version,
       cv.sha256_hash     AS current_hash,
       kg.version_no      AS known_good_version,
       kg.sha256_hash     AS known_good_hash,
       (cv.sha256_hash = kg.sha256_hash) AS integrity_ok
FROM documents d
LEFT JOIN document_versions cv ON cv.version_id = d.current_version_id
LEFT JOIN document_versions kg ON kg.document_id = d.document_id AND kg.is_known_good = 1;
CREATE VIEW v_test_matrix AS
SELECT tc.test_id, tc.title,
       b.pass_fail  AS baseline_result,
       a.pass_fail  AS after_fix_result,
       a.evidence_filename AS after_fix_evidence
FROM test_cases tc
LEFT JOIN test_runs b ON b.test_id = tc.test_id AND b.phase = 'baseline'
LEFT JOIN test_runs a ON a.test_id = tc.test_id AND a.phase = 'after_fix'
ORDER BY tc.test_id;
CREATE VIEW v_findings_summary AS
SELECT severity, status, COUNT(*) AS n
FROM findings GROUP BY severity, status;
CREATE VIEW v_incident_timeline AS
SELECT i.incident_id, i.title, i.detected_at, i.status AS incident_status,
       r.recovered_at, r.hash_verified, r.outcome
FROM incidents i
LEFT JOIN recovery_events r ON r.incident_id = i.incident_id;
