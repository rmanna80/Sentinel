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

## Recovery

- Forgot the password: `uv run sentinel-server reset-password <username>` (local machine only; signs out every session).
- Check the audit chain: `uv run sentinel-server verify-audit`.
- Agent rejected (401): enroll again from Devices > Enroll a device.
- Start fresh: stop the server and delete the data folder.
