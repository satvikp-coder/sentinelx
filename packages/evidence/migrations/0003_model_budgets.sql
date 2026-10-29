-- Hard spend guard (Prompt 9 Part 0.6): a named routing profile (e.g. "baseten_spark_open")
-- tracks cumulative estimated spend against a configured cap. `usage` already records every
-- call's actual cost; it just needed a `profile` column to group by. `budgets` holds the
-- configured limits so the guard can check them without re-reading YAML on every call.
ALTER TABLE usage ADD COLUMN profile TEXT;

CREATE TABLE budgets (
    profile      TEXT PRIMARY KEY,
    hard_cap_usd REAL NOT NULL,
    warning_usd  REAL NOT NULL,
    reserved_usd REAL NOT NULL DEFAULT 0
);
