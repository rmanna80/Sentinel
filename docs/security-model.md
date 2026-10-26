# Security model

Sentinel trusts nothing it reads: not the browser, not the agent's uploads, not external APIs, not log contents. The agent runs as the signed-in standard user, can only read, and talks only to the local server.

## Processes and privileges

| Process | Runs as | Can do | Cannot do |
| --- | --- | --- | --- |
| Server (`sentinel-server serve`) | You, standard rights | Store and score data, serve the dashboard, call integrations | Start processes (no `subprocess` anywhere in the server), listen beyond 127.0.0.1 |
| Agent (`sentinel-agent run`) | You, standard rights | Run registered read-only checks | Run a command not declared on a check class, write the registry, change settings, delete or quarantine files |
| Elevated agent (`scripts\elevated-scan.ps1`) | You, elevated after a UAC prompt | Take elevated jobs (BitLocker, Secure Boot, Security log) and exit | Run code a standard user can change: it runs only the protected copy in `C:\Program Files\Sentinel` (installed by an administrator with `install-elevated-agent.ps1`), in Python's isolated mode, from a PowerShell started with `-NoProfile`; it talks only to a server on 127.0.0.1 |

## Trust boundaries and controls

| Boundary | Threat | Control (implemented) |
| --- | --- | --- |
| Browser → server | Another website or DNS-rebinding page driving the API | Server binds 127.0.0.1 only and refuses any other bind; `HostCheckMiddleware` rejects requests whose Host is not `127.0.0.1`/`localhost` on the configured port (HTTP 421); no CORS |
| First run | Someone else claiming the admin account | Setup requires a one-time token printed to the server console and written to `setup-token.txt` in the data folder; it is deleted after use |
| Sign-in | Guessing, session theft | Argon2id hashes; 256-bit session tokens stored only as SHA-256; `HttpOnly` + `SameSite=Strict` cookie; 30-minute idle and 12-hour absolute expiry; 5 attempts per minute per client; 15-minute lockout after 10 failures; same response and same hashing work for unknown users |
| State-changing requests | CSRF | `SameSite=Strict` plus a per-session token required in `X-CSRF-Token` on every POST/PATCH/PUT/DELETE |
| Agent → server | Fake agent, stolen token | One-time enrollment codes (15 minutes, single use, stored hashed); device tokens stored hashed on the server and in Windows Credential Manager on the agent; device tokens only work on `/api/agent/*`; revocation |
| Server → agent | Using the agent as a remote shell | The server sends check IDs and validated parameters, never code; unknown IDs are ignored; each check's runner only knows that check's declared `CommandSpec`s; parameters pass strict validators (integers, hostnames/IPs/CIDRs, journal cursors, allowlisted paths) and can never start with `-`; no shell; executables resolved to fixed absolute paths from Windows known folders, not environment variables |
| Scans that touch other machines | Scanning targets nobody approved | Network and malware checks cannot be started from a generic or custom scan, and generic scans carry no parameters; network scans go only through the scope page. The agent also refuses ranges wider than /16 (IPv4) or /64 (IPv6), unspecified, multicast and link-local addresses (which covers cloud metadata endpoints) |
| Agent uploads | Oversized or poisoned data, wedged scans | Request bodies capped (32 MB for agent uploads, 2 MB elsewhere); per-result limits on findings, evidence, events, software and metrics (over-limit results are refused whole, never truncated, so nothing is wrongly resolved); evidence capped at 256 KB and event data at 16 KB per item; secrets redacted on the agent and again on the server; results only for planned checks; a scan can only be completed with a final status; a scan with no heartbeat expires and can always be cancelled |
| Findings resolution | A failed read looking like "fixed" | A finding is resolved only by a completed run of the same check and scope. Checks raise "skipped" when they cannot read something (unreadable folders, Wi-Fi state unavailable, non-English output) instead of returning an empty, passing result |
| Files the agent reads | Reading secrets | Read allowlist (system config locations and folders you add); private keys and shadow files are never read |
| Network scans | Scanning without authorization | Explicit scope list; public targets need a typed authorization sentence that is stored and audited; preview shows the exact command first; TCP connect scans only, no stealth, no scripts, no exploits |
| Secrets | Leaks via files or logs | API keys in the OS credential store (private file fallback, shown as such in the UI); never returned by the API; never written to the audit log |
| Outbound data | Silent data egress | Every integration is off until you turn it on. All server internet traffic (HTTP integrations and notification email) obeys one global switch and is logged with time, destination, purpose and a plain-words payload summary on the Outbound data page; personal values (email addresses, password-hash prefixes) are masked before they are logged |
| AI assistant | Prompt injection via logs, file names, breach titles | Local model only (loopback URL); tools are read-only database queries; tool output is wrapped as untrusted data; answers must cite stored records and invalid citations are flagged; nothing is ever executed |
| Audit log | Tampering | Entries are sealed right after their transaction commits, in commit order, each storing a sequence number and the SHA-256 of the previous entry (so concurrent requests cannot fork the chain); `GET /api/audit/verify` and `sentinel-server verify-audit` detect edited or removed entries and print the latest sequence number and hash. Limit: someone who can write the database file can rebuild the chain or drop the newest entries; note the latest hash to compare later |
| Dashboard | XSS, clickjacking | Strict CSP (`script-src 'self'`, no inline scripts, `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `nosniff`, `no-referrer` |
| Event logs | Gaps that hide activity | Windows record IDs restart after a log is cleared, so events are keyed by record ID plus time; log cursors advance only after the server has accepted the events, and local test scans never move them |
| Dependencies | Supply chain | `uv.lock` and `package-lock.json` pinned; CI runs Ruff with Bandit rules |

## Data that leaves the machine

Out of the box nothing is sent anywhere: every integration starts switched off. Integrations, when enabled, send only what the Integrations page states (package names and versions to OSV/NVD; Windows build numbers to Microsoft; CVE IDs to FIRST; your full email address to HIBP; the first five characters of a SHA-1 hash to Pwned Passwords). Every request is listed on the Outbound data page.

## Not in scope

Sentinel is a single-user, single-machine tool. It has no multi-user roles, no remote access, and no TLS between agent and server (the agent refuses plain HTTP to anything but 127.0.0.1). Remote agents reporting to one server would need mutual TLS first.
