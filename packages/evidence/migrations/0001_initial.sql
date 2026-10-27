-- Sentinel X schema v1. JSON payload columns are TEXT, validated by Pydantic before write.

CREATE TABLE scenarios (
    id         TEXT PRIMARY KEY,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE targets (
    id         TEXT PRIMARY KEY,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE sessions (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    scenario_id     TEXT REFERENCES scenarios(id),
    target_id       TEXT REFERENCES targets(id),
    arm             TEXT,
    state           TEXT NOT NULL,
    model           TEXT,
    provider        TEXT,
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    ended_at        TEXT,
    policy_version  TEXT NOT NULL,
    fixture_version TEXT,
    idempotency_key TEXT UNIQUE,
    schema_version  TEXT NOT NULL
);

CREATE TABLE actions (
    id         TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    step       INTEGER NOT NULL,
    body       TEXT NOT NULL
);

CREATE TABLE events (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(id),
    seq             INTEGER NOT NULL,
    kind            TEXT NOT NULL,
    timestamp_utc   TEXT NOT NULL,
    parent_event_id TEXT REFERENCES events(id),
    state           TEXT NOT NULL,
    source          TEXT NOT NULL,
    payload         TEXT NOT NULL,
    previous_hash   TEXT NOT NULL,
    event_hash      TEXT NOT NULL,
    schema_version  TEXT NOT NULL,
    UNIQUE (session_id, seq)
);

CREATE TABLE incidents (
    id         TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    body       TEXT NOT NULL
);

CREATE TABLE branches (
    id                TEXT PRIMARY KEY,
    parent_session_id TEXT NOT NULL REFERENCES sessions(id),
    body              TEXT NOT NULL
);

CREATE TABLE scan_findings (
    id        TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES targets(id),
    body      TEXT NOT NULL
);

CREATE TABLE patches (
    id         TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    body       TEXT NOT NULL
);

CREATE TABLE verifications (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    patch_id TEXT NOT NULL REFERENCES patches(id),
    body     TEXT NOT NULL
);

CREATE TABLE shield_rules (
    id        TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES targets(id),
    body      TEXT NOT NULL
);

CREATE TABLE escalations (
    id         TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    body       TEXT NOT NULL
);

CREATE TABLE approvals (
    id           TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL,
    subject_id   TEXT NOT NULL,
    body         TEXT NOT NULL
);

CREATE TABLE usage (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     TEXT REFERENCES sessions(id),
    provider       TEXT NOT NULL,
    model          TEXT NOT NULL,
    tokens_in      INTEGER NOT NULL,
    tokens_out     INTEGER NOT NULL,
    latency_ms     INTEGER NOT NULL,
    estimated_cost REAL,
    error          TEXT,
    timestamp      TEXT NOT NULL
);

CREATE TABLE audit (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT REFERENCES sessions(id),
    actor_id   TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    action     TEXT NOT NULL,
    from_state TEXT,
    to_state   TEXT,
    timestamp  TEXT NOT NULL,
    detail     TEXT NOT NULL
);

CREATE INDEX idx_events_session ON events(session_id, seq);
CREATE INDEX idx_actions_session ON actions(session_id, step);
CREATE INDEX idx_audit_session ON audit(session_id);
