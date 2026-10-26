# Architecture

Sentinel is three cooperating pieces on one machine, split by privilege.

```text
 Browser (React dashboard)
      │  session cookie + CSRF header, Host-checked
      ▼
 Sentinel server (FastAPI, 127.0.0.1 only, standard user) ──► SQLite (WAL; Postgres-ready)
      ▲        │                                          └──► Integrations (OSV, NVD, MSRC, KEV, EPSS,
      │        │                                               HIBP, Pwned Passwords) — every call logged
      │        └─ background loop: lease expiry, schedules, detection tick, vuln matching, intel sync, email
      │  agent pulls jobs and posts results (device token)
 Sentinel agent (standard user; elevated only per scan on request)
      │  read-only: registered PowerShell/CLI commands, registry reads, allowlisted files, psutil
      ▼
 Windows / Linux
```

## Packages

| Package | Role |
| --- | --- |
| `sentinel-core` | The wire contract: Pydantic models, `Check` base class, `CommandSpec` with parameter validation, fingerprints, redaction |
| `sentinel-agent` | Check registry, safe command runner, scan runner (timeouts, cancellation, partial results), transport, CLI, fixture context for tests and demo mode |
| `sentinel-server` | API, auth, ingestion, findings lifecycle, scoring, audit, phase modules, migrations, CLI |
| `web/` | Dashboard (React + TypeScript + Vite + Mantine + Recharts), types generated from the server's OpenAPI |

## Scan lifecycle

1. The dashboard queues a scan (`POST /api/scans`); the server records it as `queued` and audits it.
2. The agent polls `GET /api/agent/jobs/next`, claims the scan (`running`, with a lease) and builds a plan: each check is planned, skipped (with a reason, e.g. needs elevation) or not applicable. The plan is posted first, so the dashboard shows what will and will not run before anything runs.
3. Checks run in a small worker pool, each with its own timeout. Each result is posted as soon as it finishes. A crashing check becomes `error` without affecting the others; the heartbeat carries cancel requests.
4. Ingestion stores evidence (redacted, hashed, size-capped), then reconciles findings by fingerprint: new findings are created, repeated ones updated, and open findings that a **completed** run no longer reports are marked **resolved (verified)**. Skipped or failed runs never resolve anything. A resolved finding seen again is **reopened**.
5. Hooks let phase modules react: detection rules run on new log events; vulnerability matching is queued for new inventory; notifications fire for new findings.
6. Completion freezes the score, coverage and check-status counts on the scan for history. A scan whose agent stops heartbeating is marked failed when its lease expires.

## Phase modules

`sentinel_server/phases/` holds one module per feature area (detection, logs, schedules, notifications, vulns, email_security, network, assistant, analytics, reports). Each may expose a `router`, `register_hooks()` and `tick(db)`. The app factory loads whatever is present, so the core runs on its own and features plug in without editing it.

## Why these choices

- **Agent pulls, server never pushes**: the agent opens no port, and the same protocol can later serve a remote agent over mutual TLS.
- **No subprocess in the server**: a bug in a web route cannot become command execution.
- **One contract package**: the agent and server cannot disagree about the wire format.
- **SQLite first**: one user on one machine does not need a database server; SQLAlchemy models and Alembic migrations keep Postgres a configuration change.
- **Fixture context in the product**: the same fixture files drive unit tests, the demo mode, and `--record` captures of a real machine, so the first live run on new hardware can become a regression test.
