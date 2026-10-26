# Sentinel

A local-first security assistant for your own machines. Sentinel runs read-only checks on Windows and Linux, keeps every finding with the evidence behind it, watches event logs for suspicious patterns, matches installed software against vulnerability data, and explains it all in a dashboard on `http://127.0.0.1:8765`. Nothing leaves your machine unless you turn on an integration, and every request that does is listed on the Outbound data page.

> **Status: first full build, not yet run on real Windows.** Every check is tested against hand-written fixtures shaped like real command output, and the full stack is tested end to end on Linux. The first live run on your machine is the real test: see [First run on your machine](#first-run-on-your-machine).

## What it does

| Area | What you get |
| --- | --- |
| Posture scans | Firewall, Defender, Windows Update, UAC, local accounts, startup entries, LSA protection, BitLocker/Device encryption, Secure Boot, password policy, SmartScreen, Wi-Fi security, listening ports, DNS; on Linux apt updates, unattended upgrades, SSH, firewall, accounts |
| Findings | Severity, confidence, verified vs heuristic, evidence, remediation text, status workflow, owners and target dates, remediation tasks, full history. A finding is resolved only when a re-run of its check no longer reports it |
| Score | 0–100 from a documented formula, shown with coverage; "Incomplete" when too few checks ran ([docs/scoring.md](docs/scoring.md)) |
| Logs and detection | Windows Security, System and Defender logs; Linux SSH and sudo. Rules for brute force, brute force followed by success, log clearing, admin-group changes, new accounts, suspicious services, Defender detections, protection turned off, lockouts. Related alerts grouped into incidents |
| Vulnerabilities | Software inventory; version-aware matching through OSV (Linux packages, Python and npm projects), Microsoft's update guide (Windows itself), NVD for a curated set of common Windows apps; CISA KEV and EPSS for prioritisation |
| Email exposure | Have I Been Pwned breach checks for addresses you own; Pwned Passwords checks hashed in your browser |
| Network | Scope list you control, previewed TCP-connect scans with Nmap, TLS certificate and HTTP security-header checks |
| Malware | ClamAV signature scans of folders you choose. Sentinel never deletes or quarantines anything |
| Assistant | Local AI (Ollama) that answers from Sentinel's stored data with citations, through read-only tools; deterministic scan summaries and explanations that work without any AI |
| Reports | PDF, CSV and JSON with executive summary, technical findings, evidence, remediation and limitations |
| Operations | Scheduled scans, notifications with quiet hours and optional email digests, tamper-evident audit log, backups |

## Install (Windows)

Prerequisites: [uv](https://docs.astral.sh/uv/). The release zip includes the built dashboard, so Node.js is only needed if you change the dashboard (you already have Node 24, which works).

```powershell
winget install --id astral-sh.uv -e
# open a new PowerShell window so uv is on PATH
```

Keep the repository **outside OneDrive** (for example `C:\dev\sentinel`): sync can replace files mid-build and corrupt a live database.

```powershell
cd C:\dev\sentinel
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

This installs Python 3.12 (managed by uv, separate from the Microsoft Store Python) and the dependencies, rebuilds the dashboard if npm is available (add `-SkipWeb` to use the included build), and creates the database.

## Start

1. **Server** (normal PowerShell window):
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\start-server.ps1
   ```
   On the first start it prints a **setup token** (also saved to `%LOCALAPPDATA%\Sentinel\server\setup-token.txt`).
2. Open `http://127.0.0.1:8765`, enter the token, choose a username and a password of at least 12 characters.
3. **Devices → Enroll a device** shows a one-time command. Run it in a second normal PowerShell window:
   ```powershell
   uv run sentinel-agent enroll --server http://127.0.0.1:8765 --code XXXX-XXXX-XXXX
   ```
4. **Agent** (same window):
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\start-agent.ps1
   ```
5. In the dashboard, **Security Scans → New scan → Full**.

To start both at sign-in (as you, not as administrator): `scripts\register-startup.ps1`.

### Admin-only checks

BitLocker/Device encryption, Secure Boot and the Security event log need administrator rights. The everyday agent runs without them and lists those checks as skipped, with the reason.

Elevated scans never run code from the repository or its `.venv`, because your standard account (and anything running as it) can change those. Install a protected copy of the agent into `C:\Program Files\Sentinel` once, from an **administrator** PowerShell window, right after downloading or updating Sentinel:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-elevated-agent.ps1
```

Then, whenever you want the admin-only checks: queue an **elevated** scan in the dashboard and run this from a normal window:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\elevated-scan.ps1
```

Windows shows its permission prompt; the protected agent takes the elevated jobs, runs them read-only and exits. Sentinel never stores admin credentials and never elevates itself. Re-run the install script after each update so the protected copy matches.

## First run on your machine

Your machine is Windows 11 **Home** on an **Insider build** (26300). Expect:

- **Remote Desktop**: marked not applicable (Home cannot host RDP).
- **BitLocker**: Home has Device encryption instead; the check falls back to `manage-bde`, which needs the elevated scan.
- **Windows updates**: Microsoft's monthly update guide does not cover Insider builds, so missing-patch matching for Windows itself reports "no source" instead of guessing. Update history and service state are still checked.
- **Git 2.43.0** will likely be flagged once vulnerability matching is configured; upgrade with `winget upgrade Git.Git`.

Then record what your machine actually returns, so any misread can be fixed precisely:

```powershell
uv run sentinel-agent scan --type full --record recordings
```

That file holds raw command output in the same format as the test fixtures. It contains system details: keep it private (`recordings/` is git-ignored). Compare a few results against Windows Security by hand before trusting the score.

## Demo mode

`scripts\demo.ps1` starts a separate server on port 8766 in demo mode, answered by an agent that replays hand-written fixture data (a Windows 11 Home machine, or `-Fixture linux` for a Raspberry Pi). Demo data lives in its own folder and is badged everywhere. The normal server runs in production mode and **refuses fixture data**.

## Integrations

Every server-side integration starts **switched off**: until you turn one on, nothing leaves this computer. Turn them on and off on the **Integrations** page; every request is logged on the **Outbound data** tab. (Pwned Passwords is on by default because it only runs when you type a password into its check yourself, and only five characters of its hash are sent. Vulnerability matching needs OSV, Microsoft and NVD switched on.)

| Integration | Used for | What leaves your machine | Key |
| --- | --- | --- | --- |
| OSV.dev | Linux packages, Python and npm dependencies | Package names and versions | None |
| NVD API 2.0 | Curated common Windows apps | Product names | Optional free key (5 → 50 requests per 30 s) |
| Microsoft Security Update Guide | Windows itself | Nothing about you (monthly documents are downloaded) | None |
| CISA KEV | "Exploited in the wild" flag | Nothing (feed is downloaded) | None |
| FIRST EPSS | Exploit likelihood | CVE IDs | None |
| Have I Been Pwned | Email breach checks | The full email address (Core tiers have no k-anonymity search) | Paid key; Core 1 is $4.39/month billed annually |
| Pwned Passwords | Password exposure | First 5 characters of a SHA-1 hash, computed in your browser | None |
| Ollama | AI assistant | Nothing (runs on this machine) | None |
| Nmap, ClamAV | Network discovery, malware signatures | Probes to your scoped targets / signature downloads | None |

NVD note: since April 2026 NIST enriches only CVEs in CISA's KEV catalog, federal-use software and critical software; most others have no NVD product data or score. Sentinel therefore uses OSV and Microsoft's data first, uses the CVE numbering authority's score when NVD has none, records which source every score came from, and counts unenriched CVEs instead of guessing.

Optional tools:

```powershell
winget install --id Insecure.Nmap -e
winget install --id Ollama.Ollama -e ; ollama pull llama3.1:8b
uv run sentinel-agent config --add-project-path C:\dev\angel      # dependency scanning
uv run sentinel-agent config --add-malware-path $HOME\Downloads    # ClamAV folders
```

## Raspberry Pi / Linux

```bash
./scripts/install.sh            # or --skip-web to use a dashboard built elsewhere
uv run sentinel-server serve    # in one terminal
uv run sentinel-agent enroll --server http://127.0.0.1:8765 --code XXXX-XXXX-XXXX
uv run sentinel-agent run
sudo usermod -aG systemd-journal "$USER"   # lets the log check read SSH and sudo events
```

Each machine runs its own server today; remote agents reporting to one server need mutual TLS first (see Future work).

## Architecture

Three processes, split by privilege: the dashboard, an unprivileged server that owns the data and never starts processes, and an agent that can only run checks from a fixed list. Details in [docs/architecture.md](docs/architecture.md); every check in [docs/checks.md](docs/checks.md); threat model in [docs/security-model.md](docs/security-model.md); day-to-day operations in [docs/operations.md](docs/operations.md).

```text
packages/core     shared contract (models, Check base class, command specs, fingerprints, redaction)
packages/agent    checks, safe command runner, scan runner, CLI
packages/server   API, auth, ingestion, findings, scoring, audit, phase modules, migrations
web/              React + TypeScript + Vite + Mantine + Recharts dashboard
scripts/          install, start, elevated scan, startup tasks, demo, build
docs/             architecture, checks, scoring, security model, operations, conventions
```

## Development

```powershell
uv sync                         # dependencies, including dev tools
uv run pytest                   # Python tests
uv run ruff check packages      # lint
cd web; npm install; npm test; npm run build
scripts\dev.ps1                 # API + Vite hot reload on http://127.0.0.1:5173
```

Adding a check: see [docs/dev-conventions.md](docs/dev-conventions.md). In short, declare every command as a `CommandSpec` on the check class, return evidence and findings, raise `SkipCheck` when you cannot tell, add fixture tests, and register it in `ALL_CHECKS`. Regenerate the checks document with `uv run python scripts/gen_checks_doc.py`.

## Limitations

- **No check proves a device is secure.** A passing check means that one condition was not observed.
- **Not an antivirus.** Malware detection is limited to ClamAV signatures on folders you choose, Defender's own log entries, and hashes you import. Sentinel ships no threat feed.
- **Heuristics are labeled as such** (startup entries in temp folders, processes running from Downloads, unusual outbound ports) and are not proof of compromise.
- **Windows checks parse English output** where Windows offers no structured alternative (`net accounts`, `manage-bde`, `netsh wlan`); on other display languages those checks skip rather than guess.
- **Vulnerability coverage is uneven by design**: Linux packages and code dependencies are well covered by OSV; Windows itself by Microsoft's guide (not for Insider builds); other Windows apps only for the curated list. Everything else is shown as "no source" rather than "no vulnerabilities".
- **Single user, single machine.** No roles, no remote access, no TLS between agent and server.
- **Mobile and macOS are not implemented.** The check interface supports new platforms, but iOS exposes very little security posture to apps, and an Android companion would need its own project.

## Future work

- Mutual TLS so the Pi's agent can report to the Windows server.
- macOS adapter (FileVault, Gatekeeper, SIP, firewall, softwareupdate).
- Configurable detection thresholds and Sigma-style rule import.
- Signed releases and a Windows installer; the agent as a Windows service.
- Android companion app for device settings exposed through public APIs.

## License

Private project. Have I Been Pwned data is licensed CC BY 4.0 and attributed wherever it is shown.
