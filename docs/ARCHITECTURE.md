# Architecture — Argo IAM Governance Layer

This document describes the architecture of the prototype **as implemented**
in this repository, and how it relates to the existing Argo CD architecture.
Every diagram listed here is a PlantUML source in [`docs/diagrams`](diagrams/).

| # | Diagram | View |
|---|---------|------|
| 01 | [`01-current-argocd-cc.puml`](diagrams/01-current-argocd-cc.puml) | Argo CD today — Component & Connector |
| 02 | [`02-current-argocd-deployment.puml`](diagrams/02-current-argocd-deployment.puml) | Argo CD today — Deployment |
| 03 | [`03-current-argocd-modules.puml`](diagrams/03-current-argocd-modules.puml) | Argo CD today — Module (decomposition/uses) |
| 10 | [`10-proposed-cc.puml`](diagrams/10-proposed-cc.puml) | Proposed — Component & Connector |
| 11 | [`11-proposed-modules.puml`](diagrams/11-proposed-modules.puml) | Proposed — Module (uses, with enforced rules) |
| 12 | [`12-proposed-layers.puml`](diagrams/12-proposed-layers.puml) | Proposed — Layered |
| 13 | [`13-proposed-deployment.puml`](diagrams/13-proposed-deployment.puml) | Proposed — Deployment |
| 20 | [`20-seq-login-mfa.puml`](diagrams/20-seq-login-mfa.puml) | Scenario — login with password + TOTP |
| 21 | [`21-seq-jit-elevation.puml`](diagrams/21-seq-jit-elevation.puml) | Scenario — temporary privilege request/approval/expiry |
| 22 | [`22-seq-governed-sync.puml`](diagrams/22-seq-governed-sync.puml) | Scenario — privileged Argo CD operation |
| 23 | [`23-state-privilege-request.puml`](diagrams/23-state-privilege-request.puml) | State machine of a privilege request |
| 24 | [`24-data-model.puml`](diagrams/24-data-model.puml) | Data model of the IAM store |

Render them with `plantuml -tsvg docs/diagrams/*.puml` (or the VS Code / IntelliJ
PlantUML plug-ins).

---

## 1. Context

Argo CD already authenticates users (local accounts, Dex, or direct OIDC) and
authorises them with Casbin-based RBAC (`argocd-rbac-cm`). What it does not
provide is *governance* around privileged access: time-boxed elevation,
approval by a second person, explicit session control, and a tamper-evident
record of who was allowed to do what and why.

The evolution adds an **IAM Governance Layer** in front of the Argo CD API
server. Argo CD's API server, repository server and controllers are not
modified; the layer reaches Argo CD only through an adapter.

## 2. Current Argo CD architecture (summary)

* **C&C (01)** — clients (Web UI, CLI, CI) talk HTTPS/gRPC to the **API
  server**, which delegates authentication to **Dex** or an OIDC provider,
  enforces RBAC, and calls the **repository server** (manifest generation from
  Git/Helm/OCI) and the Kubernetes API. The **application controller** runs
  the reconciliation loop *desired state (repo server) vs. live state (K8s)*.
  **Redis** caches manifests and cluster state.
* **Deployment (02)** — all components run as Deployments/StatefulSets in the
  `argocd` namespace of a management cluster; credentials and RBAC policy live
  in ConfigMaps/Secrets; workload clusters are reached through stored cluster
  credentials.
* **Module (03)** — the Go code base is decomposed into `cmd`, `server`
  (per-resource API services, session, RBAC policy enforcement), `reposerver`,
  `controller`, `applicationset`, `notification_controller`, `pkg/apis`
  (CRD types), `pkg/apiclient` and `util` (rbac, session, oidc/dex, settings,
  db, git/helm/kube, cache). The diagram is conceptual and must be checked
  against the exact release analysed in the report.
* **Patterns** — client–server, shared repository (Git as source of truth),
  controller/reconciliation loop, component-based decomposition, event
  notification.

## 3. Proposed architecture

### 3.1 Component & Connector view (10)

| Component | Code | Responsibility |
|-----------|------|----------------|
| Login UI / dashboards | `argo_iam/web/auth_views.py`, `app_views.py`, `admin_views.py`, `templates/` | Password and TOTP screens, MFA enrolment, user dashboard, admin dashboard |
| IAM Gateway API | `argo_iam/web/api.py` | JSON API for CLI/CI: two-step login, bearer sessions, Argo CD operations, elevation requests, audit |
| Authentication Service | `argo_iam/auth/service.py` | Password check, lockout, MFA challenges, enrolment, hands off to the Session Manager |
| MFA | `argo_iam/auth/totp.py` | RFC 6238 TOTP, drift window, replay protection |
| Session Manager | `argo_iam/sessions/service.py` | Session creation, idle & absolute expiry, logout, revocation |
| Authorization Service | `argo_iam/authorization/service.py` | Effective role = permanent role + active grant; `require()` audits denials |
| Privilege Service | `argo_iam/privilege/service.py` | JIT request, approval (four-eyes), rejection, cancellation, revocation, expiry |
| User Service | `argo_iam/users/service.py` | Accounts, permanent roles, enable/disable, unlock, MFA reset |
| Audit Service | `argo_iam/audit/service.py` | Append-only, SHA-256 hash-chained event log, queries, chain verification |
| Argo CD Adapter | `argo_iam/argocd_adapter/` | `GovernedArgoCD` façade + `ArgoCDAdapter` port with `MockArgoCDAdapter` and `ArgoCDHttpAdapter`; RBAC policy translation |

**Connectors**

| Connector | Between | Notes |
|-----------|---------|-------|
| HTTPS + session cookie | Browser → web | `HttpOnly`, `SameSite=Lax`, `Secure` configurable; CSRF token on every form |
| HTTPS + bearer token | CLI/CI → `/api/v1` | Same two-step login; token is random, stored only as SHA-256 |
| In-process calls | web → services | Services are plain Python objects wired by `container.py` |
| SQL (SQLite) | repositories → IAM store | Only `repository.py` modules issue SQL |
| REST (Argo CD gRPC-gateway) | `ArgoCDHttpAdapter` → Argo CD API server | Service-account token (`argocd account generate-token`) |
| Policy export | IAM layer → `argocd-rbac-cm` | `render_policy_csv()` keeps Argo CD's own RBAC consistent for direct access |

### 3.2 Module view (11) and its rules

The implementation is a single Python package, `argo_iam`, whose sub-packages
are exactly the modules proposed in the project description:

```
argo_iam/
├── auth/            credential validation, hashing, TOTP, login protection
├── users/           profiles, roles, account status
├── sessions/        creation, expiration, revocation
├── authorization/   permissions, role mapping, RBAC checks
├── privilege/       temporary privilege requests, approvals, expiry
├── audit/           security event recording and queries
├── argocd_adapter/  port + mock/HTTP adapters, governed façade, RBAC translation
├── web/             login UI, dashboards, JSON API, request security
├── container.py     composition root (wires all services once)
├── common.py, clock.py, config.py, db.py   shared kernel
└── seed.py, __main__.py                    demo data and CLI
```

Each domain module follows the same internal structure:
`models.py` (domain objects) → `repository.py` (persistence) → `service.py`
(business rules). The "uses" rules are **executable** —
[`tests/test_architecture.py`](../tests/test_architecture.py) fails the build if:

1. a service module imports Flask/Werkzeug or `argo_iam.web`;
2. a domain module imports `argo_iam.argocd_adapter`;
3. anything other than a `repository.py` touches `argo_iam.db`/`sqlite3`;
4. any file except `argocd_adapter/http.py` performs network I/O;
5. the web layer calls the adapter directly instead of `GovernedArgoCD`.

Dependency direction between services (no cycles):
`auth → sessions → authorization → privilege.repository`,
`privilege.service → authorization`, `users → {sessions, privilege, authorization}`,
`argocd_adapter.governed → authorization`, and everything → `audit`.

### 3.3 Layered view (12)

Presentation (`web`) → Service layer → Domain model / Repositories → SQLite;
Service layer → Integration (`ArgoCDAdapter`) → Argo CD. Layers only call
downward.

### 3.4 Deployment view (13)

The gateway runs as its own Deployment in an `argo-iam` namespace next to
`argocd`, exposed through an Ingress with TLS. It talks to `argocd-server`
inside the cluster with a service-account token kept in a Secret. The
prototype uses SQLite on a volume and therefore one replica; moving to
PostgreSQL only replaces the repository implementations.

### 3.5 Key scenarios

* **Login (20)** — password step issues a 5-minute MFA challenge; only a valid,
  non-replayed TOTP code creates a session. Users without an authenticator get
  an *enrolment* challenge with a QR code instead.
* **JIT elevation (21)** — operator requests Admin for N minutes with a
  justification; a *different, permanent* administrator approves; the grant is
  active immediately and ends at `expires_at`. Expiry is enforced at
  permission-check time; a sweep on each request records `privilege.expired`.
* **Governed operation (22)** — production syncs require
  `applications:sync:production`; non-production syncs require
  `applications:sync`. Denials and successful operations are audited with the
  effective role and the grant that enabled them.
* **Request lifecycle (23)** — `PENDING → ACTIVE → EXPIRED | REVOKED`,
  `PENDING → REJECTED | CANCELLED`.

## 4. Roles and permissions

| Permission | Viewer | Operator | Admin | Granted by JIT? |
|------------|:-:|:-:|:-:|:-:|
| `applications:get`, `projects:get` | ✓ | ✓ | ✓ | yes |
| `applications:refresh`, `applications:sync` | | ✓ | ✓ | yes |
| `applications:sync:production`, `projects:update` | | | ✓ | yes |
| `iam:privilege:request` | ✓ | ✓ | | — |
| `iam:privilege:approve`, `iam:users:manage`, `iam:sessions:manage`, `iam:audit:read` | | | ✓ | **no** |

A temporary grant only adds the *Argo CD* permissions of the requested role.
IAM governance permissions come exclusively from the permanent role, so an
elevated user can neither approve requests (including their own) nor make
their elevation permanent. The Argo CD side is exported as `policy.csv`:

```
p, role:iam-operator, applications, sync, */*, allow
p, role:iam-operator, applications, sync, */*-prod, deny
p, role:iam-admin, applications, sync, */*-prod, allow
p, role:iam-admin, projects, update, *, allow
g, argo-iam-operators, role:iam-operator
```

## 5. Architectural patterns and where they are

| Pattern | Where |
|---------|-------|
| Layered architecture | `web` → services → repositories / adapter (§3.3) |
| Service layer | `*/service.py`; the web layer contains no business rules |
| Repository | `*/repository.py`; `AuditRepository` deliberately has no update/delete |
| Adapter (Ports & Adapters) | `ArgoCDAdapter` port; `MockArgoCDAdapter`, `ArgoCDHttpAdapter` |
| Façade | `GovernedArgoCD` bundles authorization + adapter + audit |
| MVC-like separation | Flask views (controller), Jinja templates (view), services/models (model) |
| Composition root / dependency injection | `container.py`; clock, adapter and hasher are injectable |
| Interceptor / filter chain | `web/security.py` `before_request` hooks and decorators |
| State machine | `PrivilegeRequest` statuses (§3.5, diagram 23) |
| Hash chain (tamper evidence) | `audit/service.py` |

## 6. Quality attributes and tactics

| Quality attribute | Tactic in this prototype | Verified by |
|-------------------|--------------------------|-------------|
| Security — authentication | scrypt hashing; TOTP MFA mandatory; constant-time compare; dummy hash for unknown users; lockout after 5 failures (password **or** TOTP); MFA challenge TTL + attempt limit; TOTP replay protection | `test_auth.py`, `test_passwords_totp.py` |
| Security — authorization | Least privilege by default; time-boxed elevation; four-eyes approval; governance permissions not elevatable; deny-by-default checks in services, not only in UI | `test_authorization.py`, `test_privilege.py`, `test_argocd_adapter.py` |
| Security — sessions | Random 256-bit tokens stored hashed; idle (30 min) and absolute (8 h) timeouts; revocation by user/admin; all sessions ended on role change, disable, MFA reset | `test_sessions.py`, `test_users.py` |
| Security — web | CSRF tokens, CSP, `X-Frame-Options: DENY`, `no-store` on authenticated pages, open-redirect protection, `HttpOnly`/`SameSite` cookies | `test_web.py` |
| Auditability / non-repudiation | Every security event recorded with actor, target, source IP and channel; SHA-256 hash chain detects edits and deletions | `test_audit.py` |
| Modifiability | Adapter isolates Argo CD; repositories isolate storage; composition root isolates wiring | `test_architecture.py` |
| Testability | Injectable `Clock` makes expiry deterministic; mock Argo CD; fake HTTP transport | whole suite |
| Interoperability | Real Argo CD REST adapter; RBAC policy export; standard `otpauth://` provisioning | `test_argocd_adapter.py` |
| Usability | Argo CD-like UI, inline "request access" where an action is locked, live countdown of temporary access | manual / screenshots |

## 7. Design decisions

1. **Separate layer, not an Argo CD fork.** Keeps the reconciliation core
   unchanged and lets the IAM layer evolve independently (rationale §8.5 of the
   proposal).
2. **Adapter with a mock implementation first.** The demo runs without a
   cluster; the HTTP adapter implements the same port for a real Argo CD.
3. **Expiry evaluated on read.** A grant stops working at `expires_at` even if
   no background job runs; the sweep only updates status and the audit log.
   This avoids a scheduler process in the prototype.
4. **Only Argo CD permissions are elevatable.** Prevents escalation chains
   through the governance functions themselves.
5. **One open request per user; approver ≠ requester; role must not change
   between request and approval.** Keeps approvals meaningful.
6. **Hash-chained audit log in the same store.** Detects tampering cheaply. It
   does not prevent an attacker with database access from rewriting the whole
   chain — exporting the head hash to an external system would close that gap.
7. **SQLite + single process.** Adequate for a prototype; the repository layer
   is the only code to change for PostgreSQL and multiple replicas.

## 8. Requirement traceability

| Proposal requirement | Module(s) | Tests |
|----------------------|-----------|-------|
| Username/password login | `auth`, `web.auth_views`, `web.api` | `test_auth`, `test_web`, `test_api` |
| Secure password hashing | `auth.passwords` | `test_passwords_totp` |
| MFA using TOTP | `auth.totp`, `auth.service` | `test_passwords_totp`, `test_auth` |
| Login attempt protection | `auth.service` | `test_auth` |
| Viewer / operator / administrator roles | `users.models`, `authorization.permissions` | `test_authorization` |
| Active session list, revocation, expiration | `sessions` | `test_sessions`, `test_web` |
| Temporary privileged access + approval workflow | `privilege` | `test_privilege`, `test_web`, `test_api` |
| Audit trail (login, failure, logout, MFA, privilege, role change, revocation) | `audit` + all services | `test_audit` and assertions across the suite |
| Improved login interface | `web/templates/auth` | `test_web` |
| Administrative IAM dashboard | `web.admin_views` | `test_web` |
| Argo CD adapter (mock + real) | `argocd_adapter` | `test_argocd_adapter` |

## 9. Limitations and future work

* Federation with an external OIDC IdP (the layer would become an OIDC client
  and map IdP groups to roles) is drawn but not implemented.
* The HTTP adapter is tested against a fake transport, not a live Argo CD.
* Users can still reach Argo CD directly unless Argo CD is configured to trust
  only the layer (e.g. via the exported `policy.csv` and SSO groups).
* No e-mail/chat notification of pending approvals.
* WebAuthn / recovery codes are not implemented.
