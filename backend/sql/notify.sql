-- name: EnqueueHeldNotifications :exec
-- Queue every pending held action for every configured channel. Rows that
-- already exist are left alone, so this is safe to run on every tick.
INSERT INTO notification_outbox (quarantine_id, channel)
SELECT q.id, ch
FROM quarantine q CROSS JOIN unnest(sqlc.arg(channels)::text[]) AS ch
WHERE q.status = 'pending'
ON CONFLICT DO NOTHING;

-- name: ClaimDueNotifications :many
-- Leases due rows for a few minutes while they are sent. A replica that
-- crashes mid-send leaves the lease to expire, and the row is retried.
UPDATE notification_outbox o
SET attempts = o.attempts + 1,
    next_attempt_at = NOW() + INTERVAL '2 minutes'
FROM (
    SELECT quarantine_id, channel
    FROM notification_outbox
    WHERE delivered_at IS NULL
      AND attempts < sqlc.arg(max_attempts)::int
      AND next_attempt_at <= NOW()
    ORDER BY created_at
    LIMIT sqlc.arg(batch_size)::int
    FOR UPDATE SKIP LOCKED
) due
WHERE o.quarantine_id = due.quarantine_id AND o.channel = due.channel
RETURNING o.quarantine_id::text AS quarantine_id, o.channel, o.attempts;

-- name: MarkNotificationDelivered :exec
UPDATE notification_outbox
SET delivered_at = NOW(), last_error = ''
WHERE quarantine_id = sqlc.arg(quarantine_id)::uuid AND channel = sqlc.arg(channel);

-- name: MarkNotificationFailed :exec
UPDATE notification_outbox
SET next_attempt_at = sqlc.arg(next_attempt_at), last_error = sqlc.arg(last_error)
WHERE quarantine_id = sqlc.arg(quarantine_id)::uuid AND channel = sqlc.arg(channel);
