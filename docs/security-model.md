# Security model

Sentinel trusts nothing it reads: not the browser, not the agent's uploads, not external APIs, not log contents. The agent runs as the signed-in standard user, can only read, and talks only to the local server.

## Processes and privileges

| Process | Runs as | Can do | Cannot do |
| --- | --- | --- | --- |
| Server (`sentinel-server serve`) | You, standard rights | Store and score data, serve the dashboard, call integrations | Start processes (no `subprocess` anywhere in the server), listen beyond 127.0.0.1 |
| Agent (`sentinel-agent run`) | You, standard rights | Run registered read-only checks | Run a command not declared on a check class, write the registry, change settings, delete or quarantine files |
| Elevated agent (`scripts\elevated-scan.ps1`) | You, elevated after a UAC prompt | Take one elevated job (BitLocker, Secure Boot, Security log) and exit | Anything a check does not declare; it never stores credentials or elevates itself |

## Trust boundaries and controls

| Boundary | Threat | Control (implemented) |
| --- | --- | --- |
| Browser → server | Another website or DNS-rebinding page driving the API | Server binds 127.0.0.1 only and refuses any other bind; `HostCheckMiddleware` rejects requests whose Host is not `127.0.0.1`/`localhost` on the configured port (HTTP 421); no CORS |
| First run | Someone else claiming the admin account | Setup requires a one-time token printed to the server console and written to `setup-token.txt` in the data folder; it is deleted after use |
| Sign-in | Guessing, session theft | Argon2id hashes; 256-bit session tokens stored only as SHA-256; `HttpOnly` + `SameSite=Strict` cookie; 30-minute idle and 12-hour absolute expiry; 5 attempts per minute per client; 15-minute lockout after 10 failures; same response and same hashing work for unknown users |
| State-changing requests | CSRF | `SameSite=Strict` plus a per-session token required in `X-CSRF-Token` on every POST/PATCH/PUT/DELETE |
| Agent → server | Fake agent, stolen token | One-time enrollment codes (15 minutes, single use, stored hashed); device tokens stored hashed on the server and in Windows Credential Manager on the agent; device tokens only work on `/api/agent/*`; revocation |
| Server → agent | Using the agent as a remote shell | The server sends check IDs and validated parameters, never code; unknown IDs are ignored; each check's runner only knows that check's declared `CommandSpec`s; parameters pass strict validators (integers, hostnames/IPs/CIDRs, journal cursors, allowlisted paths) and can never start with `-`; no shell; executables resolved to fixed absolute paths |
| Agent uploads | Oversized or poisoned data | Re-validated against the shared Pydantic models; evidence capped at 256 KB per item; secrets redacted on the agent and again on the server before storage |
| Files the agent reads | Reading secrets | Read allowlist (system config locations and folders you add); private keys and shadow files are never read |
| Network scans | Scanning without authorization | Explicit scope list; public targets need a typed authorization sentence that is stored and audited; preview shows the exact command first; TCP connect scans only, no stealth, no scripts, no exploits |
| Secrets | Leaks via files or logs | API keys in the OS credential store (private file fallback, shown as such in the UI); never returned by the API; never written to the audit log |
| Outbound data | Silent data egress | All server internet traffic goes through one function that logs time, destination, purpose and a plain-words payload summary to the Outbound data page; a global switch disables it |
| AI assistant | Prompt injection via logs, file names, breach titles | Local model only (loopback URL); tools are read-only database queries; tool output is wrapped as untrusted data; answers must cite stored records and invalid citations are flagged; nothing is ever executed |
| Audit log | Tampering | Every row stores the SHA-256 of the previous row; `GET /api/audit/verify` and `sentinel-server verify-audit` detect edits |
| Dashboard | XSS, clickjacking | Strict CSP (`script-src 'self'`, no inline scripts, `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `nosniff`, `no-referrer` |
| Dependencies | Supply chain | `uv.lock` and `package-lock.json` pinned; CI runs Ruff with Bandit rules |

## Data that leaves the machine

Phase 1–2 features send nothing anywhere. Integrations, when enabled, send only what the Integrations page states (package names and versions to OSV/NVD; Windows build numbers to Microsoft; CVE IDs to FIRST; your full email address to HIBP; the first five characters of a SHA-1 hash to Pwned Passwords). Every request is listed on the Outbound data page.

## Not in scope

Sentinel is a single-user, single-machine tool. It has no multi-user roles, no remote access, and no TLS between agent and server (the agent refuses plain HTTP to anything but 127.0.0.1). Remote agents reporting to one server would need mutual TLS first.
