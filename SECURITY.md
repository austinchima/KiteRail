# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| `main` (2.0.0, unreleased) | Yes |
| 1.1.x   | Yes       |
| < 1.1   | No        |

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's private vulnerability
reporting ("Security" tab → "Report a vulnerability") on
`austinchima/KiteRail` (the repository keeps its original name). You will get an acknowledgement within 3 business
days and a fix or mitigation plan within 30 days for confirmed issues.

## Security model (summary)

- **Fail closed.** Malformed ingress, policy errors, invalid decisions, and
  audit-ledger outages all refuse the action; nothing executes unaudited.
- **Trust domains.** Agent, reviewer, and admin credentials are disjoint;
  one identity cannot both act and approve (enforced at startup).
- **Reviewer sign-in.** With SSO, reviewers authenticate through the
  organization's OIDC provider (Authorization Code + PKCE, verified nonce,
  audience and issuer). The browser holds only an opaque `HttpOnly` session
  cookie, the database stores only its SHA-256, and cookie-authenticated
  changes require a CSRF header and an allowed origin. Agents never
  authenticate with cookies.
- **Notifications.** Held-action notifications never include tool
  arguments. Webhooks are signed (HMAC-SHA256 over timestamp and body;
  required in production), redirects are never followed, and Slack text is
  escaped so agent-supplied names cannot inject mentions or links.
- **Slack approvals.** Clicks are accepted only with a valid Slack request
  signature (five-minute window) from the configured workspace, and only
  from users whose Slack email is on the reviewer list; bots and
  deactivated accounts are refused. Message updates go only to Slack's own
  domains.
- **Upstream boundary.** The upstream URL is fixed by configuration (agents
  cannot choose path or query). Agent credentials, cookies, and
  `X-Elodea-*` / `Idempotency-Key` headers are stripped; the proxy asserts
  the agent identity itself.
- **Audit ledger.** SHA-256 hash chain, append-only at the database level
  (triggers), each entry bound to the policy bundle version. Anchor the head
  (`GET /api/v1/ledger/head`) externally to detect truncation.
- **Supply chain.** Release images are distroless, non-root, built from
  digest-pinned bases, signed with cosign (keyless), and shipped with an SPDX
  SBOM and SLSA build provenance.

Verify a release image:

```bash
cosign verify ghcr.io/austinchima/elodea:<version> \
  --certificate-identity-regexp 'https://github.com/austinchima/KiteRail/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
