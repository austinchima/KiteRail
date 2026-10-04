-- Held-action notifications. One row per (held action, channel) is the
-- outbox: it survives restarts, retries with backoff, and FOR UPDATE SKIP
-- LOCKED claims keep replicas from sending the same notification twice.
CREATE TABLE IF NOT EXISTS notification_outbox (
    quarantine_id UUID NOT NULL REFERENCES quarantine(id) ON DELETE CASCADE,
    channel TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (quarantine_id, channel)
);

CREATE INDEX IF NOT EXISTS idx_notification_outbox_due
    ON notification_outbox (next_attempt_at)
    WHERE delivered_at IS NULL;
