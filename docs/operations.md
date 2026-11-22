# Operations

## Where data lives

| What | Windows | Linux |
| --- | --- | --- |
| Server database, reports, setup token | `%LOCALAPPDATA%\Sentinel\server` | `~/.local/share/sentinel-server` |
| Agent config, state (log cursors), log | `%LOCALAPPDATA%\Sentinel\agent` | `~/.config/sentinel-agent` |
| Device token | Windows Credential Manager (`sentinel-agent`) | keyring, or a 0600 file if none |
| API keys | Windows Credential Manager (`sentinel-server`) | keyring, or a 0600 `secrets.json` |

Override with `SENTINEL_DATA_DIR` (server) and `SENTINEL_AGENT_HOME` (agent). Keep both outside OneDrive.

## Everyday commands

```powershell
uv run sentinel-server serve                 # dashboard + API on http://127.0.0.1:8765
uv run sentinel-agent run                    # agent, standard user
uv run sentinel-agent status                 # what the agent knows about itself
uv run sentinel-agent checks                 # every registered check
uv run sentinel-agent scan --type posture    # one local scan, printed, no server needed
uv run sentinel-agent config --add-project-path C:\dev\angel   # dependency scanning
uv run sentinel-agent config --add-malware-path $HOME\Downloads # ClamAV folders
```

## Record your machine's real output (recommended on first run)

```powershell
uv run sentinel-agent scan --type full --record recordings
```

This saves every raw command output and registry read to a JSON file shaped exactly like the test fixtures. If a check misreads your machine, that file is what fixes it. It contains system details: keep it private (`recordings/` is git-ignored).

## Backup and restore

```powershell
uv run sentinel-server backup --out C:\backups\sentinel-2026-10-26.db   # safe while running
```

Restore: stop the server, replace `sentinel.db` in the data folder with the backup (delete any `sentinel.db-wal`/`-shm` files), start the server.

## Upgrades

`git pull`, then `scripts\install.ps1`. Migrations run automatically at startup and with `sentinel-server migrate`.

## Releases

Pushing a tag such as `v0.2.0` runs `.github/workflows/release.yml`: it re-runs the checks, builds the dashboard,
and publishes `sentinel-0.2.0.zip` (the source with the dashboard already built, so installing needs no
Node.js), `SHA256SUMS.txt`, and a signed build-provenance attestation. To check a download:

```powershell
Get-FileHash sentinel-0.2.0.zip -Algorithm SHA256        # compare with SHA256SUMS.txt
gh attestation verify sentinel-0.2.0.zip --repo rmanna80/Sentinel   # proves it was built by this repo's workflow
```

To build the same zip by hand: `scripts/build-web.sh`, then `scripts/package-release.sh 0.2.0`.

## Recovery

- Forgot the password: `uv run sentinel-server reset-password <username>` (local machine only; signs out every session).
- Forgot the username: `uv run sentinel-server list-users`.
- Change the username: `uv run sentinel-server rename-user <old> <new>` (keeps the password and all data; earlier audit entries keep the old name).
- Check the audit log: `uv run sentinel-server verify-audit` (hash chain and signatures). Note the signing key
  fingerprint and latest sequence number it prints the first time you run it.
- Hand the audit log to someone else: `uv run sentinel-server export-audit --out audit.json`, then anyone can run
  `sentinel-server verify-audit-export audit.json --key-id <fingerprint>` with no database and no server. The
  verifier is one file (`sentinel_server/audit_verify.py`) that needs only the `cryptography` package.
- "Signatures were made with a signing key that is no longer in the credential store": the key was deleted or
  the data moved to another account. A new key is created automatically; earlier signatures can then only be
  checked from an export made while the old key was present.
- Agent rejected (401): enroll again from Devices > Enroll a device.
- Start fresh: stop the server and delete the data folder.

## Behavioural detection on Linux

Sentinel X on Linux reads the kernel's audit records. Three things have to be true, and each can be checked:

1. **The audit rules are loaded** (once, as root). They only record; nothing is blocked.

   ```bash
   sudo apt install auditd
   sudo cp scripts/linux/sentinel-audit.rules /etc/audit/rules.d/sentinel.rules
   sudo augenrules --load
   sudo auditctl -l | grep sentinel        # the rules should be listed
   ```

2. **The records reach the journal**, where the unprivileged agent can read them.

   ```bash
   journalctl _TRANSPORT=audit -n 5        # should print recent audit records
   ```

   If that prints nothing, turn on the journal's audit input and try again:

   ```bash
   sudo systemctl enable --now systemd-journald-audit.socket && sudo systemctl restart systemd-journald
   ```

3. **The agent's account can read the journal**: `sudo usermod -aG systemd-journal "$USER"`, then sign in again.

Then:

```bash
uv run sentinel-agent telemetry              # read what is there now and print any detections
uv run sentinel-agent run --telemetry        # keep reading and send detections to the server
```

If the journal route does not work on your distribution, a saved log can still be analysed:
`sudo cat /var/log/audit/audit.log > audit.log`, then `uv run sentinel-agent telemetry --export audit.log`.

What to expect: execve auditing is busy on a machine that builds software, and the "program run from a
temporary folder" rule is low confidence on purpose. Use `scripts/replay_dataset.py audit.log --label benign`
on a day of your own log to see the false positives per day before you rely on it.

## The AI assistant

- Answers arrive as they are written. If the model stops responding for two minutes, the reply is Sentinel's
  built-in summary of the latest scan, labelled as such, so a question never ends in a bare error.
- Every answer is checked before it is stored: cited records must exist, and a severity or status stated
  about a cited finding or alert must match the record. Mismatches are corrected at the end of the answer.
- Measure a model before trusting it:

  ```powershell
  uv run sentinel-server eval-assistant                       # the configured model
  uv run sentinel-server eval-assistant --model qwen2.5:14b   # compare another installed model
  uv run sentinel-server eval-assistant --only scope --json eval.json
  ```

  It asks about thirty questions built from your own database, each with an answer computed in advance
  (counts, severities, records that must be cited, requests that must be declined, injected instructions that
  must be ignored), and prints a pass rate by group plus the time per answer. A pass means the expected fact
  is present and nothing checkable is wrong; it does not grade the writing, so read a few answers in the JSON
  report as well. Run it after a scan, so there is data to ask about.
