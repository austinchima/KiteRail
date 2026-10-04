# Deploying Elodea in Production

## Topology

```
agents ──► [ingress / mesh, TLS] ──► Elodea (N replicas) ──► upstream tool server
                                          │
reviewers ──► reviewer API ───────────────┤
                                          ▼
                                   PostgreSQL 14+ (HA)
```

- **Stateless replicas.** All state lives in Postgres, so you can scale horizontally. The replay worker runs in every replica, and a Postgres advisory lock makes exactly one replica own each replay pass.
- **One upstream per deployment.** Every allowed or approved action goes to exactly `target_url`. Govern several tool servers by running one release per upstream.
- **Ledger throughput.** Ledger appends serialize on one chain (by design: a single total order is what makes the chain verifiable). Budget about 1–3 ms per decision on a nearby Postgres. Watch `elodea_ledger_append_duration_seconds`.

## Install with Helm

1. Create the secret, ideally from your secret manager (External Secrets, Vault, SOPS):

   ```bash
   kubectl create secret generic elodea-secrets \
     --from-literal=postgres-dsn='postgres://elodea:...@db:5432/elodea?sslmode=require' \
     --from-file=agent-keys=./agent-keys.txt \
     --from-file=reviewer-keys=./reviewer-keys.txt \
     --from-file=admin-keys=./admin-keys.txt
   ```

   Key files hold one `token:identity` per line. Tokens must be at least 24 random bytes. An identity can't appear as both an agent and a reviewer/admin.

2. Deliver policies as a ConfigMap. Changes are hot-reloaded, and a bundle that fails to compile is rejected while the previous one keeps enforcing:

   ```bash
   kubectl create configmap elodea-policies --from-file=policies/main.rego --from-file=policies/fintech/ --from-file=policies/mcp/
   ```

3. Install:

   ```bash
   helm install elodea deploy/helm/elodea \
     --set config.targetURL=https://payments.internal/mcp \
     --set secret.name=elodea-secrets --set secret.hasAdminKeys=true \
     --set policies.configMap=elodea-policies \
     --set config.allowedOrigins='{https://elodea.example.com}' \
     --set metrics.serviceMonitor.enabled=true --set networkPolicy.enabled=true
   ```

The chart runs as non-root on a read-only filesystem with all capabilities dropped. Secrets are mounted as files (`*_FILE`), never set as environment variables. `/metrics` is served on an internal-only port.

## Single sign-on for reviewers

Reviewers and admins should sign in with your identity provider, so every approval in the ledger names a verified person and offboarding happens in the IdP. Static reviewer tokens then serve only as break-glass access (set `secret.hasReviewerKeys: false` to run without them).

1. Register an OIDC web application in your IdP with redirect URI `https://<elodea host>/auth/callback`, and make the ID token carry the user's groups.
2. Add the client secret to the Elodea secret as `oidc-client-secret`.
3. Set Helm values:

```yaml
config:
  allowedOrigins: ["https://elodea-console.example.com"]   # where the console is served
oidc:
  enabled: true
  issuer: https://example.okta.com
  clientID: 0oa1b2c3d4
  redirectURL: https://elodea.example.com/auth/callback
  providerName: Okta
  reviewerGroups: [treasury-reviewers]
  adminGroups: [elodea-admins]
```

| Provider | Issuer | Notes |
|---|---|---|
| **Okta** | `https://<org>.okta.com` (or a custom authorization server) | Add a `groups` claim to the ID token, and add `groups` to `oidc.scopes`. |
| **Microsoft Entra ID** | `https://login.microsoftonline.com/<tenant-id>/v2.0` | Enable the `groups` claim (group object IDs go in `reviewerGroups`). Entra omits `email_verified`, so set `identityClaim: preferred_username`. |
| **Google Workspace** | `https://accounts.google.com` | Google ID tokens carry no groups; put an IdP that does in front (for example Okta, Keycloak, or Dex with the Google connector). |
| **Keycloak / Auth0** | the realm or tenant issuer URL | Map group membership into a `groups` claim. |

Serve the console and API on the same site (for example `console.example.com` and `elodea.example.com`) so the `SameSite=Lax` session cookie is sent. For a console on a different site, set `oidc.cookieSameSite: none` (HTTPS required). If `networkPolicy.enabled`, allow egress to the issuer on port 443.

**Try it locally.** Run a throwaway OIDC provider that lets you type any identity and claims:

```bash
docker run -d -p 8089:8080 ghcr.io/navikt/mock-oauth2-server:2.1.10
```

Start Elodea with `ELODEA_OIDC_ISSUER=http://localhost:8089/default`, `ELODEA_OIDC_CLIENT_ID=elodea-console`, `ELODEA_OIDC_CLIENT_SECRET=dev`, `ELODEA_OIDC_REDIRECT_URL=http://localhost:8080/auth/callback`, `ELODEA_OIDC_REVIEWER_GROUPS=treasury-reviewers`, and `ELODEA_ALLOWED_ORIGINS` set to the console origin. At the provider's sign-in form, enter claims such as `{"email":"you@example.com","email_verified":true,"groups":["treasury-reviewers"]}`.

## Notify reviewers of held actions

An agent waits while its action is held, so reviewers should hear about it immediately rather than when they next open the console.

- **Slack:** create an incoming webhook for the reviewers' channel, add its URL to the secret as `slack-webhook-url`, and set `secret.hasSlackWebhookURL: true`.
- **Anything else** (PagerDuty, Opsgenie, ServiceNow, a Teams workflow, your own service): set `notify.webhookURL`, add a random signing secret of 24+ bytes as `webhook-secret`, and set `secret.hasWebhookSecret: true`. The event format and signature check are in [API.md](API.md#held-action-notifications).
- Set `consoleURL` so notifications link straight to the approvals queue.

If `networkPolicy.enabled`, allow egress to the webhook hosts on port 443. Watch `elodea_notifications_total{outcome="gave_up"}`: it counts notifications abandoned after 8 attempts.

## Database

- PostgreSQL 14+ with TLS (`sslmode=require` or stricter). Migrations run automatically at startup under an advisory lock, so concurrent rollouts are safe.
- The ledger is append-only through triggers. For defence against a compromised database owner, run Elodea as a role that owns neither the tables nor the trigger functions, and grant it only `INSERT`/`SELECT` on `ledger`.
- Back up with point-in-time recovery. Never restore the ledger partially; verify the chain after any restore.

## Anchor the audit ledger

The hash chain proves the ledger is internally consistent. External anchoring proves it wasn't truncated or rewritten. Record the head on a schedule somewhere Elodea's database owner can't change:

```bash
# e.g. a CronJob every 15 minutes
curl -sf -H "Authorization: Bearer $REVIEWER_TOKEN" http://elodea:8080/api/v1/ledger/head \
  | aws s3 cp - "s3://audit-anchors/elodea/$(date -u +%FT%TZ).json" --object-lock-mode COMPLIANCE ...

# Later: verify the chain still contains an anchored head
curl -s -H "Authorization: Bearer $REVIEWER_TOKEN" \
  "http://elodea:8080/api/v1/ledger/verify?anchor_seq=4212&anchor_hash=2c26b46b..."
```

Stream the full chain to your SIEM with `GET /api/v1/ledger/export` (NDJSON, resumable with `after_seq`).

## Monitoring

| Signal | Alert when |
|---|---|
| `/readyz` | not ready for more than 1 minute (Postgres unreachable or no policy loaded) |
| `elodea_ledger_append_failures_total` | any increase: requests are failing closed |
| `elodea_ledger_append_duration_seconds` | p99 above 50 ms |
| `elodea_policy_reloads_total{result="failure"}` | any increase: a bad bundle was rejected |
| `elodea_replay_outcomes_total{outcome="blocked_by_policy"}` | any increase: review the policy change |
| `elodea_replay_outcomes_total{outcome=~"replay_upstream_5xx|replay_error"}` | sustained increase |
| `GET /api/v1/ledger/verify` (scheduled) | `valid == false` |
| `elodea_notifications_total{outcome="gave_up"}` | any increase: reviewers were not told about a held action |

`elodea_policy_info{policy_version}` and `elodea_build_info{version}` show what each replica is running.

## Production checklist

- [ ] `environment: production` (enables strict validation)
- [ ] TLS: a local certificate, or `tls_terminated_upstream: true` behind an ingress/mesh
- [ ] Exact `allowed_origins` for the reviewer console
- [ ] Reviewers and admins sign in with SSO (`oidc`); static reviewer/admin tokens kept only as break-glass, or removed
- [ ] Separate agent, reviewer, and admin identities with high-entropy tokens from a secret manager
- [ ] `ELODEA_TARGET_AUTH_TOKEN_FILE` if the upstream requires service authentication
- [ ] Postgres with TLS, PITR backups, and a least-privilege application role
- [ ] Policies delivered from version control; CI runs `opa check --strict` and `opa test`
- [ ] Ledger head anchored externally on a schedule; verify job alerting on `valid == false`
- [ ] Held-action notifications to Slack or a signed webhook, with `consoleURL` set
- [ ] Alerts from the monitoring table above
- [ ] Release image verified with cosign (see `SECURITY.md`) and pinned by digest
