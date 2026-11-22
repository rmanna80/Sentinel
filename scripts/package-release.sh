#!/usr/bin/env bash
# Build a release zip: the source at HEAD plus the built dashboard, with a checksum file beside it.
# Usage: scripts/package-release.sh <version>     e.g. scripts/package-release.sh 0.2.0
# The zip is what README's install steps expect: unpack it and run scripts\install.ps1 -SkipWeb (no Node.js).
set -euo pipefail

version="${1:?usage: scripts/package-release.sh <version>}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
name="sentinel-${version}"
out="$repo/dist"
static="packages/server/src/sentinel_server/static"

cd "$repo"
[[ -f "$static/index.html" ]] || { echo "Build the dashboard first: scripts/build-web.sh" >&2; exit 1; }

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$out"
git archive --format=tar --prefix="$name/" HEAD | tar -x -C "$stage"
mkdir -p "$stage/$name/$static"
cp -R "$static/." "$stage/$name/$static/"
rm -f "$out/$name.zip"
(cd "$stage" && zip -qr "$out/$name.zip" "$name")
(cd "$out" && sha256sum "$name.zip" > SHA256SUMS.txt)
echo "Wrote $out/$name.zip"
cat "$out/SHA256SUMS.txt"
