# Security Policy

## Supported versions

| Version | Supported |
| :------ | :-------- |
| 1.1.x   | ✅        |
| < 1.1   | ❌        |

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Email **security@cyberguard.example** (replace with your team's real address /
security.txt contact) with:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- affected version / commit,
- any suggested remediation.

You will get an acknowledgement within **3 business days** and a status update at
least every **7 days** until the report is resolved.

### Disclosure

- We follow **coordinated disclosure**. Please give us **90 days** before any
  public write-up, or until a fix ships — whichever is sooner.
- We will credit reporters in the release notes unless you ask us not to.
- We do not currently run a paid bug-bounty program.

## Scope

In scope: `cyberguard_api/` (the ML API + gateway), `cyberguard_mcp_server.py`,
`frontend/`, the container image, and the CI/CD configuration.

Out of scope: findings that require a compromised host or CI runner, volumetric
DoS, and issues in third-party dependencies already tracked upstream (report
those to the dependency and let us know the advisory id).

## Hardening baseline

Production deployments MUST set:

| Variable | Requirement |
| :------- | :---------- |
| `APP_ENV` | `production` |
| `API_KEYS` | non-empty; rotate on staff change |
| `CORS_ORIGINS` | explicit origin list, no `*` |
| `TELEMETRY_BACKEND` | not `mock` |
| `RATE_LIMIT_STORAGE_URI` | `redis://…` when `WEB_CONCURRENCY > 1` |
| `CYBERGUARD_MODEL_MANIFEST` | read-only path **outside** `cyberguard_api/models/` |
| `FORWARDED_ALLOW_IPS` | ingress / load-balancer IPs only, never `*` |
| `HSTS_MAX_AGE` | `31536000` (auto in prod) |

The process **fails closed** at startup if `API_KEYS`, `CORS_ORIGINS`, the
telemetry backend, the manifest location, or the rate-limit store are
misconfigured for `APP_ENV=production`.

## Dependency management

- `cyberguard_api/requirements.txt` is the pinned source of truth.
- CI regenerates a hashed lock and installs with `pip install --require-hashes`.
- `pip-audit` runs in CI on every pull request and nightly.
