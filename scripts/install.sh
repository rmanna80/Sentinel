#!/usr/bin/env bash
# Install Sentinel on Linux (e.g. the Raspberry Pi 5). Run as your normal user from the repository folder.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v uv >/dev/null || { echo "Install uv first: curl -LsSf https://astral.sh/uv/install.sh | sh"; exit 1; }
uv python install 3.12
uv sync --locked
if [[ "${1:-}" != "--skip-web" ]]; then
  command -v npm >/dev/null || { echo "npm not found: install Node.js LTS or rerun with --skip-web"; exit 1; }
  ./scripts/build-web.sh
fi
uv run sentinel-server migrate
cat <<'EOF'
Sentinel is installed.
  Server: uv run sentinel-server serve          (http://127.0.0.1:8765)
  Agent:  uv run sentinel-agent run              (after enrolling from the dashboard)
For the log check, add yourself to the adm or systemd-journal group:  sudo usermod -aG systemd-journal "$USER"
EOF
