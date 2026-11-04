#!/usr/bin/env bash
# Put a wireless NIC into monitor mode for the deauth IDS (receive-only).
# Usage: sudo ./setup_monitor.sh [iface]
# Default physical iface: wlan1  →  creates/uses wlan1mon-style monitor name.

set -euo pipefail

IFACE="${1:-wlan1}"
MON="${IFACE}mon"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0 $IFACE" >&2
  exit 1
fi

if ! iw dev "$IFACE" info &>/dev/null; then
  echo "Interface $IFACE not found. Available:" >&2
  iw dev >&2 || true
  exit 1
fi

# Prefer airmon-ng if present (handles NetworkManager quirks).
if command -v airmon-ng &>/dev/null; then
  airmon-ng check kill || true
  airmon-ng start "$IFACE" || true
  # airmon-ng may create ${IFACE}mon or rename in place
  if iw dev | grep -q mon; then
    echo "Monitor interface ready:"
    iw dev
    exit 0
  fi
fi

ip link set "$IFACE" down
iw dev "$IFACE" set type monitor
ip link set "$IFACE" up
# Optional rename for clarity
if [[ "$IFACE" != "$MON" ]] && ! iw dev "$MON" info &>/dev/null; then
  ip link set "$IFACE" name "$MON" 2>/dev/null || MON="$IFACE"
fi

echo "Monitor mode on: $MON"
iw dev "$MON" info
echo
echo "Run IDS: sudo python3 deauth_ids.py -i $MON"
