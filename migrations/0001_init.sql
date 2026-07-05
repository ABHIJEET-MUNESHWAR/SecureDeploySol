-- SecureDeploySol off-chain schema.
--
-- `proposals` mirrors on-chain upgrade proposals (consumed by the feature-gated
-- Postgres proposal store). `findings` is LIST-partitioned by severity to
-- demonstrate horizontal partitioning: high-severity partitions can be indexed,
-- retained, and queried independently from informational noise.

CREATE TABLE IF NOT EXISTS proposals (
    id           BIGINT      PRIMARY KEY,
    program_id   TEXT        NOT NULL,
    build_hash   TEXT        NOT NULL,
    proposer     TEXT        NOT NULL,
    eta          BIGINT      NOT NULL,
    approvals    INT         NOT NULL DEFAULT 0,
    threshold    INT         NOT NULL,
    status       TEXT        NOT NULL DEFAULT 'pending',
    created_at   BIGINT      NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_proposals_program ON proposals (program_id);
CREATE INDEX IF NOT EXISTS idx_proposals_status  ON proposals (status);
CREATE INDEX IF NOT EXISTS idx_proposals_created ON proposals (created_at DESC);

-- Security findings, LIST-partitioned by severity.
CREATE TABLE IF NOT EXISTS findings (
    id           TEXT        NOT NULL,
    program_id   TEXT        NOT NULL,
    threat_code  TEXT        NOT NULL,
    severity     TEXT        NOT NULL,
    title        TEXT        NOT NULL,
    resolved     BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at   BIGINT      NOT NULL,
    PRIMARY KEY (id, severity)
) PARTITION BY LIST (severity);

CREATE TABLE IF NOT EXISTS findings_critical PARTITION OF findings FOR VALUES IN ('critical');
CREATE TABLE IF NOT EXISTS findings_high     PARTITION OF findings FOR VALUES IN ('high');
CREATE TABLE IF NOT EXISTS findings_medium   PARTITION OF findings FOR VALUES IN ('medium');
CREATE TABLE IF NOT EXISTS findings_low      PARTITION OF findings FOR VALUES IN ('low');
CREATE TABLE IF NOT EXISTS findings_info     PARTITION OF findings FOR VALUES IN ('info');

CREATE INDEX IF NOT EXISTS idx_findings_program  ON findings (program_id);
CREATE INDEX IF NOT EXISTS idx_findings_open     ON findings (resolved) WHERE resolved = FALSE;
