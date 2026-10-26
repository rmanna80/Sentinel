#!/usr/bin/env bash
# Build the dashboard and install it into the server's static folder.
# Usage: scripts/build-web.sh
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
web="$repo/web"
static="$repo/packages/server/src/sentinel_server/static"

command -v npm >/dev/null || { echo "npm not found. Install Node.js LTS (22.22 or newer)." >&2; exit 1; }

cd "$web"
if [[ -f package-lock.json ]]; then
  npm ci --no-audit --no-fund
else
  npm install --no-audit --no-fund
fi
npm run build

[[ -f "$web/dist/index.html" ]] || { echo "Build produced no dist/index.html" >&2; exit 1; }

rm -rf "$static"
mkdir -p "$static"
cp -R "$web/dist/." "$static/"
echo "Dashboard installed in $static"
