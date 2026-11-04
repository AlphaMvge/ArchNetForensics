#!/usr/bin/env bash
#===============================================================================
#  ArchNetForensics — Uninstaller Script
#===============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[-] Please run uninstall.sh with sudo or as root.${NC}"
    exit 1
fi

echo -e "${CYAN}[*] Removing ArchNetForensics binaries...${NC}"
rm -f /usr/local/bin/archnetforensics
rm -f /usr/local/bin/archnet-deauth-ids
rm -f /usr/local/bin/archnet-setup-monitor

echo -e "${GREEN}[+] ArchNetForensics successfully uninstalled.${NC}"

