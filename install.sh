#!/usr/bin/env bash
#===============================================================================
#  ArchNetForensics — System-wide Installer for Arch Linux
#===============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[-] Please run install.sh with sudo or as root.${NC}"
    exit 1
fi

echo -e "${CYAN}[*] Installing ArchNetForensics suite...${NC}"

# Install main forensics binary
install -Dm755 bin/archnetforensics.sh /usr/local/bin/archnetforensics

# Install companion Wi-Fi IDS
if [[ -f companion/deauth_ids.py ]]; then
    echo -e "${CYAN}[*] Installing companion Wi-Fi IDS (archnet-deauth-ids)...${NC}"
    install -Dm755 companion/deauth_ids.py /usr/local/bin/archnet-deauth-ids
fi

# Install helper script
if [[ -f companion/setup_monitor.sh ]]; then
    install -Dm755 companion/setup_monitor.sh /usr/local/bin/archnet-setup-monitor
fi

echo -e "${GREEN}[+] ArchNetForensics installation complete!${NC}"
echo -e "${CYAN}[*] Usage:${NC}"
echo -e "    sudo archnetforensics           # Launch network forensics & anomaly suite"
echo -e "    sudo archnet-deauth-ids         # Launch companion Wi-Fi deauth/disassoc IDS"

