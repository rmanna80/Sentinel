#!/usr/bin/env bash
# Passive Wi-Fi survey for Sentinel's Field Data section.
#
# WHAT THIS DOES: it listens. It puts a monitor-mode-capable adapter (e.g. the Alfa AWUS036ACHM) into
# monitor mode and runs airodump-ng, which passively records the access points broadcasting around you
# into a CSV file. It then restores the adapter. You upload the CSV in the dashboard under Field Data,
# where Sentinel flags an access point imitating one of your own SSIDs (a possible evil twin) and any of
# your own networks that are open or using WEP.
#
# WHAT THIS DOES NOT DO: it does not transmit, deauthenticate anyone, capture handshakes, or attack any
# network. It is receive-only situational awareness of your own radio environment. Only run it where you
# are allowed to; monitor-mode listening is passive, but know your local rules.
#
# Requires: aircrack-ng (airodump-ng, airmon-ng), root. Linux only (your Pi 5 or Ubuntu box).
#   Usage: sudo ./wifi-survey.sh <wlan-interface> [seconds]
#   Example: sudo ./wifi-survey.sh wlan1 120
set -euo pipefail

IFACE="${1:-}"
SECONDS_TO_RUN="${2:-120}"
if [[ -z "$IFACE" ]]; then
  echo "Usage: sudo $0 <wlan-interface> [seconds]   (e.g. sudo $0 wlan1 120)" >&2
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root (monitor mode needs it): sudo $0 $*" >&2
  exit 2
fi
for tool in airmon-ng airodump-ng; do
  command -v "$tool" >/dev/null || { echo "$tool not found. Install aircrack-ng (sudo apt install aircrack-ng)." >&2; exit 2; }
done

OUTDIR="${SENTINEL_SURVEY_DIR:-$HOME/sentinel-surveys}"
mkdir -p "$OUTDIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
PREFIX="$OUTDIR/survey-$STAMP"

MON=""
cleanup() {
  [[ -n "$MON" ]] && airmon-ng stop "$MON" >/dev/null 2>&1 || true
  # airodump writes several formats; keep only the CSV, which is what Sentinel reads.
  rm -f "$PREFIX"-01.cap "$PREFIX"-01.kismet.csv "$PREFIX"-01.kismet.netxml "$PREFIX"-01.log.csv 2>/dev/null || true
}
trap cleanup EXIT

echo "Enabling monitor mode on $IFACE (listen-only)..."
airmon-ng check kill >/dev/null 2>&1 || true
airmon-ng start "$IFACE" >/dev/null
MON="$(iw dev 2>/dev/null | awk '/Interface/ {print $2}' | grep -E 'mon|^wlan' | head -1)"
MON="${MON:-${IFACE}mon}"

echo "Listening for ${SECONDS_TO_RUN}s. No packets are transmitted. Press Ctrl+C to stop early."
# --output-format csv keeps it to the one file Sentinel parses; airodump only receives.
timeout "${SECONDS_TO_RUN}s" airodump-ng --output-format csv --write "$PREFIX" "$MON" >/dev/null 2>&1 || true

CSV="$PREFIX-01.csv"
if [[ -f "$CSV" ]]; then
  echo ""
  echo "Survey saved: $CSV"
  echo "Next: open Sentinel, go to Field Data, and upload this file (kind: Wi-Fi survey)."
  echo "Add your own SSIDs and access-point MAC addresses under Known networks first, so Sentinel can"
  echo "tell your networks apart from everyone else's."
else
  echo "No CSV was produced. Check that $IFACE supports monitor mode and that there is Wi-Fi activity nearby." >&2
  exit 1
fi
