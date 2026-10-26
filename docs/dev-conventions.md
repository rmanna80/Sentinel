# Sentinel developer conventions

Read this before adding code. The foundation (shared contract, agent runner, server core) is done and tested; new work plugs into it.

## Layout

- `packages/core/src/sentinel_core/` — the wire contract. `models.py` (Pydantic models + enums), `checks.py` (the `Check` base class and `CheckContext`/`SystemProbe` protocols), `commands.py` (`CommandSpec`, `ParamKind`, `powershell()` helper), `fingerprint.py`, `redaction.py`. **Do not change the contract** without a very good reason; if you must, keep it backward compatible.
- `packages/agent/src/sentinel_agent/` — the agent. Checks live in `checks/<common|windows|linux|network|malware>/`; every check class must be added to `ALL_CHECKS` in `checks/__init__.py`. Reference checks: `checks/common/resources.py`, `checks/windows/firewall.py`, `checks/windows/uac.py`. Fixture-driven test context: `sentinel_agent/testing.py` (`FixtureContext`, `windows_host()`, `linux_host()`, `ps_json()`, `reg()`).
- `packages/server/src/sentinel_server/` — FastAPI server. `models.py` holds **every table for every phase** (already final; do not edit it — if a column is truly missing, say so in your report instead). Phase features are modules in `phases/` (see `phases/__init__.py` for the plug-in contract: optional `router`, `register_hooks()`, `tick(db)`).

## Agent checks

- A check never starts a process directly. It declares every command as a module-level `CommandSpec` constant, lists them in the class attribute `commands = (...)`, and calls `ctx.run(spec, **params)` / `ctx.run_json(spec, ...)`. The runner refuses anything not declared on that check class.
- PowerShell: use `sentinel_core.commands.powershell(name, script)`. Scripts are fixed constants ending in `| ConvertTo-Json -Depth N -Compress`. Cast enums to strings inside PowerShell (`[string]$_.Prop`) because `ConvertTo-Json` emits enums as numbers. A single result comes back as an object, not a list: wrap with `sentinel_agent.safe_commands.as_list(...)`.
- Parameters: only `ParamKind` kinds; `INT` may be embedded in an argument; every other kind must be a whole argument. Never build a script string at runtime.
- Registry: `ctx.read_registry("HKLM", path, name, view="64")`, `ctx.read_registry_values(...)`, `ctx.list_registry_subkeys(...)` (read-only). Files: `ctx.read_text(path)` (allowlisted roots only), `ctx.list_dir`, `ctx.path_exists`. System telemetry: `ctx.system.*` (never import psutil in a check).
- Raise `SkipCheck("reason shown to the user")` when the check cannot run (tool missing, cmdlet unavailable, access denied). Raise `NotApplicable("reason")` when it turns out not to apply. Override `applicable(host)` for edition/OS conditions known up front (e.g. Windows Home has no Remote Desktop host). Never guess: an unreadable value is a skip, not a pass.
- Findings: use `checks._util.finding(...)`. `subject_key` must identify the specific thing (it feeds the dedupe fingerprint). `kind`: `VERIFIED` for directly observed state, `HEURISTIC` for suspicious-but-unproven, `INFORMATIONAL` for context. Remediation is advice text; nothing is ever executed.
- Profiles: `posture` (default), `inventory` (emits `CheckOutput.software`), `logs` (emits `CheckOutput.events`), `network` and `malware` (need params, never part of a full scan).
- Tests: every check gets fixture tests in `packages/agent/tests/`. Fixtures are hand-written to match the real output format and must say so; they are not recordings. Use `FixtureContext(windows_host(edition="Home"), {...})`.

## Server phase modules

- User routes depend on `deps.current_auth` (session + CSRF are enforced there). Return Pydantic response models so the OpenAPI schema is typed (the dashboard is generated from it). Prefix routes with `/api/<area>`.
- Always write an audit entry (`audit.record(db, auth.actor, "<area>.<verb>", ...)`) for state changes. Never put secrets in audit details.
- Hooks (`services/hooks.py`) run inside the agent's upload request: keep them fast and database-only. Anything that needs the network goes in `tick(db)`.
- Outbound HTTP only through `integrations/http.py:request(...)`, with an honest `payload_summary`. Tests install a mock transport with `integrations.http.set_transport(httpx.MockTransport(handler))` (reset it to `None` afterwards). The sandbox has no internet; never depend on live calls in tests.
- Secrets: `services/secrets.py` (`get_secret("hibp_api_key")`, `"nvd_api_key"`, `"smtp_password"`). Settings: `services/app_settings.py` (`get_setting(db, "integrations")`, `integration_enabled(db, "osv")`).
- Notifications: `services/notify.py:notify(db, severity=..., kind=..., title=..., dedupe_key=...)`.
- Findings created outside the agent (e.g. vulnerabilities) go through `services/findings.reconcile(...)` with `source="vuln_matcher"` so dedupe, verified resolution and reopening behave the same everywhere; then `hooks.fire("findings_created", db, device, created + reopened)`.
- Never invent data: a metric that cannot be computed is returned as `null`/unavailable, not estimated.

## Tests and tooling

- Run tests with `.venv/bin/python -m pytest <path> -q` from the repo root (avoid `uv run` while other work may be syncing). Server tests use the fixtures in `packages/server/tests/conftest.py` (`browser`, `make_agent`, `settings`, `production`); do not edit that file, add local fixtures in your own test module instead.
- Lint: `.venv/bin/ruff check <paths>`. Line length 125.
- No new Python dependencies. Available: fastapi, sqlalchemy 2, pydantic 2, httpx, defusedxml, reportlab, argon2-cffi, keyring, psutil, respx (tests).
