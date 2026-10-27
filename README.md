# Argo IAM Governance Layer

A Python prototype of an **identity and access governance layer for
[Argo CD](https://argo-cd.readthedocs.io/)**, built for the CS411 Software
Architecture project *"Architectural Analysis and IAM Governance Extension for
Argo CD"*.

Argo CD already authenticates users and enforces RBAC. This layer sits in front
of the Argo CD API and adds governance around privileged access — without
changing Argo CD's API server, repository server or controllers:

- **Login with mandatory MFA** — password step + TOTP (RFC 6238), first-login
  authenticator enrolment with QR code, lockout after repeated failures,
  replay protection.
- **Session management** — list, revoke, idle and absolute expiry, all sessions
  ended on role change / disable / MFA reset.
- **Role-aware authorization** — Viewer, Operator, Admin; production syncs need
  Admin.
- **Just-in-time privilege elevation** — request a higher role for 15–240 min
  with a justification; a *different* permanent administrator approves; access
  expires automatically.
- **Tamper-evident audit trail** — every authentication, authorization,
  session, privilege and Argo CD event in a SHA-256 hash chain; filter, export
  as CSV, verify.
- **Administrative IAM dashboard** — users and roles, approvals, active
  sessions, audit log, generated Argo CD `policy.csv`.
- **Argo CD adapter** — an in-memory mock for demos and a real REST adapter for
  an Argo CD API server, behind the same interface.

Architecture documentation: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) ·
PlantUML diagrams: [`docs/diagrams/`](docs/diagrams/)

## Quick start

Requires Python 3.9+ built against OpenSSL with `hashlib.scrypt` (python.org
and Homebrew builds; the macOS system Python 3.9 has no scrypt). Commands
below use the virtual environment's interpreter directly, so nothing needs
activating.

macOS / Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m argo_iam run --seed
```

Windows (PowerShell):

```powershell
py -3 -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
.venv\Scripts\python -m argo_iam run --seed
```

Open <http://127.0.0.1:8080>. `--seed` creates the demo users below (once).

### Demo users

All demo users have the password **`ArgoDemo!2026`**.

| User | Role | Notes |
|------|------|-------|
| `alice` | Admin | approver |
| `sam` | Admin | second approver (security team) |
| `oscar` | Operator | can sync non-production; requests elevation for production |
| `vera` | Viewer | read-only |
| `nina` | Operator | no authenticator yet → enrols MFA at first login |

Seeded users have an authenticator secret already. In demo mode you can print
the code their authenticator would show:

```bash
.venv/bin/python -m argo_iam totp oscar
```

```powershell
.venv\Scripts\python -m argo_iam totp oscar
```

### Five-minute demo script

1. Sign in as **oscar** (password + `totp oscar`). On *Applications*, the
   production tiles show 🔒 *Admin only*; syncing `guestbook-staging` works.
2. *Access & elevation* → request **Admin** for 60 minutes with a
   justification.
3. Sign out, sign in as **alice** → *Elevation requests* → **Approve**.
4. Sign in as **oscar** again → the header shows *Admin (temporary) · 59m left*;
   sync `guestbook-prod`.
5. As **alice**: *Audit log* shows the whole story (request, approval, sync
   with `elevated=True` and the request id) and the hash-chain check; *Active
   sessions* lets you revoke oscar's session; *Users & roles* lets you
   disable, unlock or reset MFA.
6. Sign in as **nina** to see first-login MFA enrolment with a QR code.

## JSON API

The IAM Gateway API mirrors the UI for CLI and CI use. macOS / Linux:

```bash
# 1. password step -> challenge
curl -s -X POST localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"oscar","password":"ArgoDemo!2026"}'
# 2. TOTP step -> session token
curl -s -X POST localhost:8080/api/v1/auth/mfa \
  -H 'Content-Type: application/json' \
  -d '{"challenge_token":"<challenge>","code":"<totp>"}'
# 3. use it
curl -s localhost:8080/api/v1/applications -H 'Authorization: Bearer <token>'
```

Windows (PowerShell):

```powershell
$r = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/auth/login -ContentType 'application/json' -Body '{"username":"oscar","password":"ArgoDemo!2026"}'
$t = Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/auth/mfa -ContentType 'application/json' -Body (@{challenge_token=$r.challenge_token; code=(.venv\Scripts\python -m argo_iam totp oscar)} | ConvertTo-Json)
Invoke-RestMethod -Uri http://localhost:8080/api/v1/applications -Headers @{Authorization="Bearer $($t.token)"}
```

| Method & path | Purpose |
|---------------|---------|
| `POST /api/v1/auth/login` · `POST /api/v1/auth/mfa` · `POST /api/v1/auth/logout` | two-step login, logout |
| `GET /api/v1/me` | base/effective role, permissions, active elevation |
| `GET /api/v1/applications` · `POST /api/v1/applications/{name}/sync` | governed Argo CD access (`{"dry_run": true}` supported) |
| `GET/POST /api/v1/privilege-requests` | own requests / create; `?status=pending` for approvers |
| `POST /api/v1/privilege-requests/{id}/{approve\|reject\|revoke\|cancel}` | decisions |
| `GET /api/v1/audit?type=auth&user=oscar&outcome=failure` | audit query + chain status (admins) |

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `ARGO_IAM_DB` | `instance/argo_iam.sqlite3` | SQLite file |
| `ARGO_IAM_SECRET_KEY` | random per start | signs the login-flow cookie; set it for stable restarts |
| `ARGO_IAM_SESSION_IDLE_MINUTES` / `ARGO_IAM_SESSION_ABSOLUTE_MINUTES` | 30 / 480 | session timeouts |
| `ARGO_IAM_MAX_FAILED_LOGINS` / `ARGO_IAM_LOCKOUT_MINUTES` | 5 / 15 | lockout policy |
| `ARGO_IAM_MAX_PRIVILEGE_MINUTES` | 240 | longest elevation |
| `ARGO_IAM_COOKIE_SECURE` | `0` | set `1` behind HTTPS |
| `ARGO_IAM_DEMO_MODE` | `1` | enables the `totp` helper command |
| `ARGO_IAM_ARGOCD_MODE` | `mock` | `http` to use a real Argo CD |
| `ARGOCD_SERVER_URL` / `ARGOCD_AUTH_TOKEN` / `ARGOCD_VERIFY_TLS` | — | real Argo CD API and service-account token |

Set a variable for the current shell session, then start the server:

```bash
export ARGO_IAM_DB=/path/to/argo_iam.sqlite3
```

```powershell
$env:ARGO_IAM_DB = "C:\path\to\argo_iam.sqlite3"
```

Other commands (macOS / Linux):

```bash
.venv/bin/python -m argo_iam policy          # print generated Argo CD policy.csv
.venv/bin/python -m argo_iam verify-audit    # verify the audit hash chain
.venv/bin/python -m argo_iam create-admin bob --email bob@example.com
```

Other commands (Windows PowerShell):

```powershell
.venv\Scripts\python -m argo_iam policy          # print generated Argo CD policy.csv
.venv\Scripts\python -m argo_iam verify-audit    # verify the audit hash chain
.venv\Scripts\python -m argo_iam create-admin bob --email bob@example.com
```

## Project structure

```
argo_iam/
  auth/            password hashing (scrypt), TOTP, login + lockout, MFA challenges
  users/           user model, roles, account administration
  sessions/        session manager (create / expire / revoke)
  authorization/   permission catalogue, role mapping, effective-role checks
  privilege/       JIT request → approval → expiry workflow
  audit/           hash-chained audit store and queries
  argocd_adapter/  adapter port, mock + HTTP adapters, governed façade, policy export
  web/             Flask login UI, dashboards, admin panel, JSON API, request security
  container.py     composition root
docs/              ARCHITECTURE.md and PlantUML diagrams
tests/             unit, integration, web, API and architecture-conformance tests
```

## Tests

```bash
.venv/bin/python -m pytest
```

```powershell
.venv\Scripts\python -m pytest
```

The suite covers the RFC 6238 test vectors, every login/lockout/MFA path,
session expiry with a controllable clock, the JIT lifecycle and its abuse
cases (self-approval, elevated approver, stale role), audit tampering
detection, the mock and HTTP Argo CD adapters, full browser and API flows, and
**architecture conformance** (`tests/test_architecture.py` enforces the module
dependency rules from the architecture document).

## Known limitations

* The session cookie `Secure` flag is off by default for local HTTP demos. Set `ARGO_IAM_COOKIE_SECURE=1` behind HTTPS.
* The audit page, the admin overview and `GET /api/v1/audit` verify the whole hash chain on every request. With about 20,000 events a request takes roughly 2.7 seconds, and the cost grows linearly.
* The audit hash chain does not detect deletion of the newest entries. Anchoring the head hash outside the database would close this gap (see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)).
* Password hashing uses `hashlib.scrypt`, so Python must be built against OpenSSL. The macOS system Python 3.9 lacks it. Use a Homebrew or python.org build.
* The HTTP adapter is tested with a fake transport, not a live Argo CD.

## Scope

This is a course prototype. It is not hardened for production use: see
*Limitations* in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#9-limitations-and-future-work).
