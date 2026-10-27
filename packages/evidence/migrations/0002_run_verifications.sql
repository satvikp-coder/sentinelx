-- Run verifications (VerifierResult) share the verifications table with repair verifications.
-- patch_id becomes nullable; a CHECK keeps each row to exactly one kind.
CREATE TABLE verifications_new (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL DEFAULT 'REPAIR',
    patch_id   TEXT REFERENCES patches(id),
    session_id TEXT REFERENCES sessions(id),
    body       TEXT NOT NULL,
    CHECK ((kind = 'REPAIR' AND patch_id IS NOT NULL)
        OR (kind = 'RUN' AND session_id IS NOT NULL))
);
INSERT INTO verifications_new (id, kind, patch_id, body)
    SELECT id, 'REPAIR', patch_id, body FROM verifications;
DROP TABLE verifications;
ALTER TABLE verifications_new RENAME TO verifications;
CREATE INDEX idx_verifications_session ON verifications(session_id);
