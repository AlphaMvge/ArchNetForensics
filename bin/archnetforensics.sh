#!/usr/bin/env bash
#===============================================================================
#  ArchNetForensics (archnetforensics.sh)
#-------------------------------------------------------------------------------
#  High-Fidelity Network Diagnostics, Anomaly Detection & LLM Forensics Suite
#  Optimized for Arch Linux | Tailored for LLM Analysis (Grok / Claude / GPT)
#  Author: AlphaMvge (Midnight Mass Collective)
#
#  Runs simultaneously (with graceful degradation for missing tools):
#    - tcpdump full-traffic captures (rotating pcaps, IoT chatter, DNS audit)
#    - Rolling ping sweeps & latency sampling across entire subnet
#    - Traceroutes (ICMP, TCP/443, UDP) to gateway and external targets
#    - ARP table & arp-scan hardware vendor fingerprinting
#    - nmap deep host discovery, OS detection, service/version audits
#    - mtr continuous path quality baselining (packet loss / jitter)
#    - Socket & service connection state inventories (ss)
#    - Bandwidth & flow sampling (iftop / vnstat)
#    - Real-time anomaly detection (SYN backlog spikes, ARP spoofing, failed neighbors)
#    - Automated LLM / Grok executive report synthesis (GROK_ANALYSIS.md)
#===============================================================================
set -u
set -o pipefail

VERSION="1.0.0"

# Colors for terminal styling
if [[ -t 1 ]]; then
  CLR_RESET="\033[0m"
  CLR_BOLD="\033[1m"
  CLR_RED="\033[1;31m"
  CLR_GREEN="\033[1;32m"
  CLR_YELLOW="\033[1;33m"
  CLR_BLUE="\033[1;34m"
  CLR_MAGENTA="\033[1;35m"
  CLR_CYAN="\033[1;36m"
  CLR_GRAY="\033[0;90m"
else
  CLR_RESET=""
  CLR_BOLD=""
  CLR_RED=""
  CLR_GREEN=""
  CLR_YELLOW=""
  CLR_BLUE=""
  CLR_MAGENTA=""
  CLR_CYAN=""
  CLR_GRAY=""
fi

# Print banner
print_banner() {
  cat << "EOF"
    ___             __    _   __     __  ______                               _          
   /   |  __________/ /_  / | / /__  / /_/ ____/___  ________  ____  _____(_)________
  / /| | / ___/ ___/ __ \/  |/ / _ \/ __/ /_  / __ \/ ___/ _ \/ __ \/ ___/ / ___/ ___/
 / ___ |/ /  / /__/ / / / /|  /  __/ /_/ __/ / /_/ / /  /  __/ / / (__  ) / /__(__  ) 
/_/  |_/_/   \___/_/ /_/_/ |_/\___/\__/_/    \____/_/   \___/_/ /_/____/_/\___/____/  
EOF
  printf "${CLR_CYAN}  Arch Linux Network Forensics, Anomaly Detection & LLM Telemetry Suite ${CLR_GRAY}v%s${CLR_RESET}\n" "$VERSION"
  printf "${CLR_GRAY}  Maintained by AlphaMvge | Companion Wi-Fi IDS Included${CLR_RESET}\n\n"
}

# Helper functions
TS() { date "+%Y-%m-%d %H:%M:%S%z"; }
TS_NICE() { date "+%Y-%m-%d %H:%M:%S"; }

# Defaults
DURATION_MIN=15
OUTROOT=""
IFACE_OVERRIDE=""
SUBNET_OVERRIDE=""
FILTER=""
INSTALL_ALL=0
SKIP_MISSING=0
PCAP_ROT_MB=512
PCAP_MAX_FILES=100
EXT_TARGETS=(1.1.1.1 8.8.8.8 9.9.9.9)
KEY_PORTS="22,80,443,445,3389,502,161,5900,8080"

show_help() {
  print_banner
  cat << EOF
Usage: sudo ./archnetforensics.sh [OPTIONS] [duration_minutes] [output_dir]

Options:
  -d, --duration <min>   Run duration in minutes (default: 15)
  -o, --output <dir>     Output directory for forensic artifacts
  -i, --iface <interface> Override primary capture interface (default: default route interface)
  -s, --subnet <cidr>    Override scan subnet (default: auto-detected /24)
  -y, --install-all      Non-interactive: auto-install all missing Arch packages
      --skip-missing     Non-interactive: skip all missing tools without prompting
  -f, --filter <bpf>     Optional BPF filter for packet captures (e.g., 'not port 22')
      --wifi-ids         Launch companion Wi-Fi Deauth IDS monitor
  -v, --version          Show version
  -h, --help             Show this help menu

Examples:
  sudo ./archnetforensics.sh
  sudo ./archnetforensics.sh -d 30 -o /tmp/network-audit
  sudo ./archnetforensics.sh -y -d 10 -i wlan0
  sudo ./archnetforensics.sh --wifi-ids
EOF
  exit 0
}

# Parse options
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      ;;
    -v|--version)
      echo "ArchNetForensics v$VERSION"
      exit 0
      ;;
    -y|--install-all)
      INSTALL_ALL=1
      shift
      ;;
    --skip-missing)
      SKIP_MISSING=1
      shift
      ;;
    -d|--duration)
      DURATION_MIN="$2"
      shift 2
      ;;
    -o|--output)
      OUTROOT="$2"
      shift 2
      ;;
    -i|--iface)
      IFACE_OVERRIDE="$2"
      shift 2
      ;;
    -s|--subnet)
      SUBNET_OVERRIDE="$2"
      shift 2
      ;;
    -f|--filter)
      FILTER="$2"
      shift 2
      ;;
    --wifi-ids)
      SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
      COMPANION_IDS="$SCRIPT_DIR/../companion/deauth_ids.py"
      if [[ ! -f "$COMPANION_IDS" ]]; then
        COMPANION_IDS="$SCRIPT_DIR/deauth_ids.py"
      fi
      if [[ -f "$COMPANION_IDS" ]]; then
        exec python3 "$COMPANION_IDS" "$@"
      else
        echo -e "${CLR_RED}[-] Companion deauth_ids.py not found.${CLR_RESET}" >&2
        exit 1
      fi
      ;;
    -*)
      echo "Unknown option: $1" >&2
      echo "Run with --help for usage." >&2
      exit 1
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

# Handle positional arguments
if [[ ${#POSITIONAL[@]} -gt 0 && -n "${POSITIONAL[0]}" ]]; then
  DURATION_MIN="${POSITIONAL[0]}"
fi
if [[ ${#POSITIONAL[@]} -gt 1 && -n "${POSITIONAL[1]}" ]]; then
  OUTROOT="${POSITIONAL[1]}"
fi

# Root check
if [[ $EUID -ne 0 ]]; then
  echo -e "${CLR_RED}[!] ERROR: ArchNetForensics requires root privileges.${CLR_RESET}" >&2
  echo -e "    Please run with sudo: ${CLR_BOLD}sudo $0${CLR_RESET}" >&2
  exit 1
fi

print_banner

#-------------------------------------------------------------------------------
# ARCH LINUX DEPENDENCY CHECKER & INTERACTIVE INSTALLER
#-------------------------------------------------------------------------------
declare -A TOOL_PKG_MAP=(
  ["tcpdump"]="tcpdump"
  ["nmap"]="nmap"
  ["traceroute"]="traceroute"
  ["mtr"]="mtr"
  ["arp-scan"]="arp-scan"
  ["ss"]="iproute2"
  ["ip"]="iproute2"
  ["ping"]="iputils"
  ["iftop"]="iftop"
  ["vnstat"]="vnstat"
  ["jq"]="jq"
)

# Ordered list of core diagnostic tools to verify
TOOLS_TO_CHECK=(tcpdump nmap traceroute mtr arp-scan ss ip ping iftop vnstat jq)
MISSING_TOOLS=()
MISSING_PKGS_SET=()

need() { command -v "$1" >/dev/null 2>&1; }

for tool in "${TOOLS_TO_CHECK[@]}"; do
  if ! need "$tool"; then
    MISSING_TOOLS+=("$tool")
    pkg="${TOOL_PKG_MAP[$tool]:-$tool}"
    # Deduplicate package names
    found=0
    for p in "${MISSING_PKGS_SET[@]:-}"; do
      if [[ "$p" == "$pkg" ]]; then found=1; break; fi
    done
    if [[ $found -eq 0 ]]; then
      MISSING_PKGS_SET+=("$pkg")
    fi
  fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  printf "${CLR_YELLOW}[!] Dependency Check: %d tool(s) missing on your system:${CLR_RESET}\n" "${#MISSING_TOOLS[@]}"
  for tool in "${MISSING_TOOLS[@]}"; do
    pkg="${TOOL_PKG_MAP[$tool]:-$tool}"
    printf "    ${CLR_GRAY}•${CLR_RESET} %-12s ${CLR_GRAY}(Arch pacman package: %s)${CLR_RESET}\n" "$tool" "$pkg"
  done
  echo

  INSTALL_CHOICE=""
  if [[ $INSTALL_ALL -eq 1 ]]; then
    INSTALL_CHOICE="1"
  elif [[ $SKIP_MISSING -eq 1 ]]; then
    INSTALL_CHOICE="3"
  elif [[ -t 0 ]]; then
    printf "${CLR_BOLD}How would you like to handle missing dependencies?${CLR_RESET}\n"
    printf "  ${CLR_GREEN}[1]${CLR_RESET} Install ALL missing packages via pacman (Recommended)\n"
    printf "  ${CLR_CYAN}[2]${CLR_RESET} Selectively prompt for each tool\n"
    printf "  ${CLR_YELLOW}[3]${CLR_RESET} Skip missing tools and continue running with available probes\n"
    printf "${CLR_BOLD}Enter choice [1-3] (default: 1): ${CLR_RESET}"
    read -r user_in
    INSTALL_CHOICE="${user_in:-1}"
  else
    # Non-interactive without flags: default to skipping to prevent hang
    INSTALL_CHOICE="3"
  fi

  case "$INSTALL_CHOICE" in
    1)
      if command -v pacman >/dev/null 2>&1; then
        printf "\n${CLR_CYAN}[*] Running: pacman -S --needed --noconfirm %s${CLR_RESET}\n" "${MISSING_PKGS_SET[*]}"
        if pacman -S --needed --noconfirm "${MISSING_PKGS_SET[@]}"; then
          printf "${CLR_GREEN}[+] Dependencies successfully installed!${CLR_RESET}\n\n"
        else
          printf "${CLR_RED}[-] Pacman installation encountered an error. Continuing with available tools...${CLR_RESET}\n\n"
        fi
      else
        printf "${CLR_RED}[-] pacman not found. Continuing with available tools...${CLR_RESET}\n\n"
      fi
      ;;
    2)
      if command -v pacman >/dev/null 2>&1; then
        for tool in "${MISSING_TOOLS[@]}"; do
          pkg="${TOOL_PKG_MAP[$tool]:-$tool}"
          printf "Install %s (package: %s)? [y/N]: " "$tool" "$pkg"
          read -r resp
          if [[ "$resp" =~ ^[Yy]$ ]]; then
            pacman -S --needed --noconfirm "$pkg" || true
          fi
        done
        echo
      fi
      ;;
    3|*)
      printf "${CLR_YELLOW}[*] Skipping missing dependencies. Probes requiring them will be bypassed.${CLR_RESET}\n\n"
      ;;
  esac
fi

# Refresh tool availability
have() { need "$1"; }

# Setup Interface & Subnet
if [[ -n "$IFACE_OVERRIDE" ]]; then
  IFACE="$IFACE_OVERRIDE"
else
  IFACE="$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')"
  : "${IFACE:=eth0}"
fi

if [[ -n "$SUBNET_OVERRIDE" ]]; then
  SUBNET="$SUBNET_OVERRIDE"
else
  SUBNET="$(ip -o -4 addr show "$IFACE" 2>/dev/null | awk '{print $4}' | head -1)"
  if [[ -n "$SUBNET" ]]; then
    SUBNET="${SUBNET%/*}/24"
  else
    SUBNET="192.168.1.0/24"
  fi
fi

GATEWAY="$(ip -o -4 route show default 2>/dev/null | awk '{print $3; exit}')"
: "${GATEWAY:=unknown}"

# Gather capture interfaces (exclude lo, veth, docker)
if [[ -z "${IFACES:-}" ]]; then
  DETECTED_IFACES=$(ip -o link show 2>/dev/null | grep 'state UP' | awk -F': ' '{print $2}' \
           | awk '{print $1}' | grep -vE '^(lo|veth|docker|br-)' || true)
  IFACES=($DETECTED_IFACES)
fi
if [[ ${#IFACES[@]} -eq 0 ]]; then
  IFACES=("$IFACE")
fi

ALL_NETS=("$SUBNET")
if [[ -z "$OUTROOT" ]]; then
  OUTROOT="$(pwd)/archnet-forensics-$(date +%Y%m%d-%H%M%S)"
fi
OUT="$OUTROOT"
mkdir -p "$OUT"/{pcap,logs,reports,json,inventory}
MANIFEST="$OUT/run-manifest.txt"

log() {
  printf '%s | %s\n' "$(TS)" "$*" >> "$MANIFEST"
}

# Environment snapshot
{
  echo "# ArchNetForensics Environment Snapshot $(TS)"
  echo "Kernel: $(uname -a)"
  echo "Interface: $IFACE"
  echo "IP Addrs:"
  ip -o addr 2>/dev/null || true
  echo "Routing:"
  ip route 2>/dev/null || true
  echo "Initial Neighbor Table:"
  ip -o -4 neigh show 2>/dev/null || true
} > "$OUT/inventory/environment.txt" 2>&1

log "=== ARCHNET FORENSICS START ==="
log "Iface: $IFACE | Subnet: $SUBNET | Gateway: $GATEWAY | Duration: ${DURATION_MIN}m"
log "Output: $OUT"

# Print Configuration Card
printf "${CLR_BOLD}══════════════════════════════════════════════════════════════════════${CLR_RESET}\n"
printf "  ${CLR_CYAN}Target Interface :${CLR_RESET} %-16s ${CLR_CYAN}Default Gateway :${CLR_RESET} %s\n" "$IFACE" "$GATEWAY"
printf "  ${CLR_CYAN}Subnet Scope     :${CLR_RESET} %-16s ${CLR_CYAN}Run Duration    :${CLR_RESET} %d minutes\n" "$SUBNET" "$DURATION_MIN"
printf "  ${CLR_CYAN}Capture Devices  :${CLR_RESET} %s\n" "${IFACES[*]}"
printf "  ${CLR_CYAN}Output Directory :${CLR_RESET} %s\n" "$OUT"
printf "${CLR_BOLD}══════════════════════════════════════════════════════════════════════${CLR_RESET}\n\n"

# Probe Status Matrix
printf "${CLR_BOLD}Forensic Probe Status Matrix:${CLR_RESET}\n"
show_probe_status() {
  local name="$1"
  local req_tool="$2"
  local desc="$3"
  if have "$req_tool"; then
    printf "  ${CLR_GREEN}[ACTIVE]${CLR_RESET}  %-24s ${CLR_GRAY}(%s)${CLR_RESET}\n" "$name" "$desc"
    return 0
  else
    printf "  ${CLR_YELLOW}[SKIPPED]${CLR_RESET} %-24s ${CLR_GRAY}(requires %s - not installed)${CLR_RESET}\n" "$name" "$req_tool"
    return 1
  fi
}

show_probe_status "Packet Ring-Buffer" "tcpdump" "Full traffic, IoT chatter, DNS live logs"
show_probe_status "Subnet Ping Sweep" "ping" "Continuous ping latency & discovery sweep"
show_probe_status "Path Traceroutes" "traceroute" "ICMP, TCP/443 & UDP path mapping"
show_probe_status "ARP Discovery" "arp-scan" "MAC & hardware vendor identification"
show_probe_status "Nmap Deep Audit" "nmap" "OS detection, service versions, port audit"
show_probe_status "MTR Path Quality" "mtr" "Jitter, latency, packet loss baselines"
show_probe_status "Socket Telemetry" "ss" "TCP/UDP listening & established sockets"
show_probe_status "Bandwidth Profiler" "iftop" "Flow & throughput metrics"
show_probe_status "Anomaly Sentinel" "ss" "SYN backlog spikes & MAC spoof watch"
echo

# Tracking PIDs
declare -A PIDS

# Helper to run jobs in background
run() {
  local name="$1"; shift
  {
    echo "### started $(TS): $*"
    "$@" 2>&1
    echo "### finished $(TS) (exit $?)"
  } >> "$OUT/logs/$name.log" &
  PIDS[$name]=$!
  log "LAUNCHED: $name (pid ${PIDS[$name]})"
}

#============================= 1) TCPDUMP CAPTURES ==============================
BPF="not broadcast and not multicast ${FILTER:+and ($FILTER)}"
if have tcpdump; then
  for cap_if in "${IFACES[@]}"; do
    tcpdump -i "$cap_if" -U -n \
      -w "$OUT/pcap/${cap_if}-full-%Y%m%d-%H%M%S.pcapng" \
      -G 3600 -s 0 -W "$PCAP_MAX_FILES" -C "$PCAP_ROT_MB" -z gzip \
      $BPF > /dev/null 2>&1 &
    PIDS[pcap-$cap_if]=$!

    tcpdump -i "$cap_if" -n -s 0 \
      -w "$OUT/pcap/${cap_if}-iot-discovery.pcapng" \
      "port 5353 or port 1900 or port 5355 or (port 67 or port 68) or port 137 or port 138" > /dev/null 2>&1 &
    PIDS[iot-$cap_if]=$!

    tcpdump -i "$cap_if" -n -l \
      "tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 or icmp[icmptype] == 8 or icmp[icmptype] == 3 or icmp[icmptype] == 11" \
      > "$OUT/logs/${cap_if}-suspicious-flags.log" 2>&1 &
    PIDS[flags-$cap_if]=$!

    tcpdump -i "$cap_if" -n -l "port 53" > "$OUT/logs/${cap_if}-dns-live.log" 2>&1 &
    PIDS[dns-$cap_if]=$!
  done
  log "LAUNCHED: full-traffic + IoT + DNS + anomaly captures"
fi

#============================= 2) PING SWEEP / LATENCY ==========================
if have ping; then
  (
    : > "$OUT/inventory/ping-sweep.csv"
    echo "timestamp,ip,status,avg_ms" >> "$OUT/inventory/ping-sweep.csv"
    END_TIME=$(( $(date +%s) + DURATION_MIN*60 ))
    while (( $(date +%s) < END_TIME )); do
      NMAP_PING=""
      for NET in "${ALL_NETS[@]}"; do
        [[ -z "$NET" ]] && continue
        if have nmap; then
          NMAP_PING+="$(nmap -sn -PE "$NET" -oG - 2>/dev/null | awk '/Up$/{print $2}')"$'\n'
        else
          for i in $(seq 1 254); do
            ip="${NET%.*}.$i"
            ping -c1 -W1 "$ip" >/dev/null 2>&1 && NMAP_PING+="$ip"$'\n'
          done
        fi
      done
      for ip in $NMAP_PING; do
        [[ -z "$ip" ]] && continue
        ms=$(ping -c 2 -W 1 "$ip" 2>/dev/null | awk -F'/' '/rtt|round-trip/{print int($5)}')
        echo "$(TS),$ip,up,${ms:-timeout}" >> "$OUT/inventory/ping-sweep.csv"
      done
      sleep 45
    done
  ) & PIDS[ping-sweep]=$!
  log "LAUNCHED: rolling ping sweep"
fi

#============================= 3) TRACEROUTES ===================================
if have traceroute; then
  (
    {
      echo "# Gateway Path Audit $(TS)"
      [[ "$GATEWAY" != "unknown" ]] && traceroute -n -w 2 -q 2 "$GATEWAY" 2>/dev/null || true
      for target in "${EXT_TARGETS[@]}"; do
        echo; echo "=== Traceroute to $target (ICMP) ==="
        traceroute -n -w 2 -q 2 -I "$target" 2>/dev/null || true
        echo; echo "=== Traceroute to $target (TCP 443) ==="
        traceroute -n -w 2 -q 2 -T -p 443 "$target" 2>/dev/null || true
      done
    } > "$OUT/reports/traceroutes.txt" 2>&1
  ) & PIDS[traceroutes]=$!
  log "LAUNCHED: traceroutes"
fi

#============================= 4) ARP DEVICE DISCOVERY ==========================
(
  if have arp-scan; then
    for pass in 1 2 3; do
      echo "# arp-scan pass $pass $(TS)"
      arp-scan --localnet --numeric --retry 2 2>/dev/null || true
      sleep 60
    done
  fi
  echo; echo "# ip neighbor table snapshot $(TS)"
  ip -o neigh show 2>/dev/null || true
) > "$OUT/inventory/arp-devices.txt" 2>&1 &
PIDS[arp-discovery]=$!
log "LAUNCHED: arp device discovery"

#============================= 5) NMAP DEEP DISCOVERY ===========================
if have nmap; then
  (
    echo "# Nmap Host Discovery $(TS)"
    nmap -sn -PE --system-dns "${ALL_NETS[@]}" -oN "$OUT/reports/nmap-hosts.txt" 2>/dev/null || true
    echo "# Nmap Service & OS Fingerprint $(TS)"
    nmap -sV --version-intensity 3 -p "$KEY_PORTS" -T4 --open -oN "$OUT/reports/nmap-services.txt" "${ALL_NETS[@]}" 2>/dev/null || true
  ) > "$OUT/reports/nmap-report.log" 2>&1 &
  PIDS[nmap]=$!
  log "LAUNCHED: nmap deep audit"
fi

#============================= 6) MTR PATH QUALITY ==============================
if have mtr; then
  (
    for target in "${EXT_TARGETS[@]}"; do
      mtr -rwzc 20 -i 5 -n "$target" > "$OUT/reports/mtr-quality-$target.txt" 2>&1 &
    done
    wait
  ) & PIDS[mtr]=$!
  log "LAUNCHED: mtr quality probes"
fi

#============================= 7) SOCKET / SERVICE INVENTORY ====================
if have ss; then
  (
    echo "# Initial Listening Sockets $(TS)"
    ss -tulnp 2>/dev/null || true
    echo; echo "# Initial Established Connections $(TS)"
    ss -tunap 2>/dev/null || true
  ) > "$OUT/inventory/sockets.txt" 2>&1
  log "LAUNCHED: socket inventory"
fi

#============================= 8) BANDWIDTH / FLOW SAMPLING =====================
(
  if have iftop; then
    iftop -i "$IFACE" -nNb -t -s 60 2>/dev/null | awk '!seen[$0]++' > "$OUT/reports/bandwidth-samples.txt" 2>&1 || true
  fi
  if have vnstat; then
    timeout 60 vnstat -l -i "$IFACE" > "$OUT/reports/vnstat-live.txt" 2>&1 || true
  fi
) & PIDS[bandwidth]=$!

#============================= 9) LIVE ANOMALY DETECTION ========================
(
  ANOMALY_LOG="$OUT/reports/anomaly-watch.txt"
  : > "$ANOMALY_LOG"
  END_TIME=$(( $(date +%s) + DURATION_MIN*60 ))
  while (( $(date +%s) < END_TIME )); do
    {
      if have ip; then
        ip -s neigh show 2>/dev/null | awk '$0 ~ /FAILED|INCOMPLETE/ {print "NEIGHBOR-ANOMALY: " $0}'
      fi
      if have ss; then
        ss -tan state syn-recv 2>/dev/null | awk 'NR>1{c[$4]++}END{for(i in c) if(c[i]>10) print "SYN-FLOOD-ALERT: High SYN backlog on", i, "("c[i]" connections)"}'
      fi
      if [[ -f /proc/net/arp ]]; then
        cat /proc/net/arp | awk 'NR>1{mac[$4]++; ip[$4]=ip[$4]" "$1}
          END{for(m in mac) if(mac[m]>1 && m!="00:00:00:00:00:00") print "ARP-SPOOF-ALERT: Duplicate MAC detected!", m, "associated with IPs:" ip[m]}'
      fi
    } >> "$ANOMALY_LOG" 2>&1
    sleep 20
  done
) & PIDS[anomaly-watch]=$!
log "LAUNCHED: live anomaly sentinel"

#============================= 10) JSON TELEMETRY STREAM ========================
(
  END_TIME=$(( $(date +%s) + DURATION_MIN*60 ))
  while (( $(date +%s) < END_TIME )); do
    {
      arp_cnt=$(ip neigh 2>/dev/null | wc -l || echo 0)
      tcp_cnt=$(ss -tln 2>/dev/null | tail -n +2 | wc -l || echo 0)
      udp_cnt=$(ss -uln 2>/dev/null | tail -n +2 | wc -l || echo 0)
      est_cnt=$(ss -tn state established 2>/dev/null | tail -n +2 | wc -l || echo 0)
      printf '{"ts":"%s","iface":"%s","arp_hosts":%s,"tcp_ports":%s,"udp_ports":%s,"established":%s}\n' \
        "$(TS)" "$IFACE" "$arp_cnt" "$tcp_cnt" "$udp_cnt" "$est_cnt"
    } >> "$OUT/json/telemetry.ndjson"
    sleep 30
  done
) & PIDS[json-telemetry]=$!

#-------------------------------------------------------------------------------
# CLEANUP & SIGNAL HANDLING
#-------------------------------------------------------------------------------
STOPPING=0
cleanup() {
  if [[ $STOPPING -eq 1 ]]; then return; fi
  STOPPING=1
  printf "\n\n${CLR_YELLOW}[*] Concluding captures and stopping background probes...${CLR_RESET}\n"
  for name in "${!PIDS[@]}"; do
    kill "${PIDS[$name]}" 2>/dev/null || true
  done
  pkill -P $$ 2>/dev/null || true
  pkill -f "tcpdump -i ${IFACE}" 2>/dev/null || true
  generate_llm_report
  print_summary
  exit 0
}

trap cleanup SIGINT SIGTERM

#-------------------------------------------------------------------------------
# LLM REPORT GENERATOR (GROK / CLAUDE / CHATGPT READY)
#-------------------------------------------------------------------------------
generate_llm_report() {
  local LLM_FILE="$OUT/GROK_ANALYSIS.md"
  log "Synthesizing LLM Forensic Report: $LLM_FILE"

  # Gather summary stats
  local host_count=0
  if [[ -f "$OUT/inventory/ping-sweep.csv" ]]; then
    host_count=$(awk -F',' 'NR>1 && $3=="up"{print $2}' "$OUT/inventory/ping-sweep.csv" | sort -u | wc -l)
  fi

  local anomaly_count=0
  if [[ -f "$OUT/reports/anomaly-watch.txt" ]]; then
    anomaly_count=$(grep -cE "ALERT|ANOMALY" "$OUT/reports/anomaly-watch.txt" || echo 0)
  fi

  local dns_queries_count=0
  for f in "$OUT"/logs/*-dns-live.log; do
    if [[ -f "$f" ]]; then
      local cnt
      cnt=$(wc -l < "$f" 2>/dev/null || echo 0)
      dns_queries_count=$((dns_queries_count + cnt))
    fi
  done

  {
    cat << EOF
# 🛡️ ArchNetForensics — Network Telemetry & Forensic Dossier
> **Generated for LLM Ingestion (Grok / Claude / ChatGPT)**
> Generated at: $(TS_NICE) | Suite: ArchNetForensics v$VERSION | Target Subnet: $SUBNET

---

## 🤖 Instructions for AI Security Analyst (System Prompt)
*Copy and paste this entire document directly into Grok, Claude, or ChatGPT with the prompt below:*

\`\`\`text
You are a Senior Security Operations Center (SOC) & Network Forensics Analyst.
Review the network telemetry data provided below and prepare a clear, structured executive briefing for the user:
1. EXECUTIVE VERDICT: Is this network healthy, or are there indicators of compromise, rogue devices, or unauthorized scans?
2. DEVICE INVENTORY & ROGUE AUDIT: Analyze the discovered hosts. Flag any suspicious, unknown MAC vendors or misplaced IoT hardware.
3. EXPOSED PORTS & SERVICES: Review the open port findings. Highlight any high-risk ports (e.g. SMB 445, RDP 3389, Telnet 23, Modbus 502, unencrypted HTTP).
4. ANOMALIES & ATTACK SIGNALS: Evaluate SYN floods, duplicate MAC address alerts (ARP spoofing), or suspicious DNS queries.
5. REMEDIATION ACTION PLAN: Provide 3-5 prioritized, beginner-friendly instructions to harden the network.
\`\`\`

---

## 📊 1. Executive Environment Snapshot
| Metric | Value |
|---|---|
| **Capture Interface** | \`$IFACE\` |
| **Subnet Scope** | \`$SUBNET\` |
| **Default Gateway** | \`$GATEWAY\` |
| **Discovery Run Duration** | ${DURATION_MIN} minutes |
| **Active Hosts Discovered** | **$host_count** unique devices |
| **Security Anomalies Flagged** | **$anomaly_count** alert events |
| **Live DNS Queries Audited** | $dns_queries_count requests |

---

## 🖥️ 2. Discovered Network Devices & ARP Inventory
EOF

    if [[ -f "$OUT/inventory/arp-devices.txt" ]]; then
      echo '```text'
      grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$OUT/inventory/arp-devices.txt" | head -n 40 || true
      echo '```'
    elif [[ -f "$OUT/inventory/ping-sweep.csv" ]]; then
      echo '```text'
      awk -F',' 'NR>1 && $3=="up"{print "IP: " $2 " (Avg Latency: " $4 " ms)"}' "$OUT/inventory/ping-sweep.csv" | sort -u | head -n 40
      echo '```'
    else
      echo "*No ARP or ping sweep inventory tools were active.*"
    fi

    cat << EOF

---

## 🔓 3. Port & Service Discovery (Nmap Audit)
EOF

    if [[ -f "$OUT/reports/nmap-services.txt" ]]; then
      echo '```text'
      grep -E '^[0-9]+/tcp' "$OUT/reports/nmap-services.txt" | head -n 50 || echo "No open standard ports detected."
      echo '```'
    else
      echo "*Nmap port scan was not available or produced no open port telemetry.*"
    fi

    cat << EOF

---

## 🚨 4. Threat & Anomaly Sentinel Findings
EOF

    if [[ -f "$OUT/reports/anomaly-watch.txt" && -s "$OUT/reports/anomaly-watch.txt" ]]; then
      echo '```text'
      head -n 50 "$OUT/reports/anomaly-watch.txt"
      echo '```'
    else
      echo "✅ **Clean baseline**: No ARP spoofing (duplicate MACs), SYN backlog floods, or neighbor failures observed during the run."
    fi

    cat << EOF

---

## 🌐 5. DNS Chatter & Domain Resolution Sample
EOF

    local found_dns=0
    for f in "$OUT"/logs/*-dns-live.log; do
      if [[ -f "$f" && -s "$f" ]]; then
        found_dns=1
        echo "Top unique DNS lookups observed:"
        echo '```text'
        awk '{for(i=1;i<=NF;i++) if($i ~ /\.[a-z]{2,}/) print $i}' "$f" | sort | uniq -c | sort -nr | head -n 25 || true
        echo '```'
        break
      fi
    done
    if [[ $found_dns -eq 0 ]]; then
      echo "*No DNS queries captured (tcpdump was not run or no port 53 traffic occurred).*"
    fi

    cat << EOF

---

## 🔌 6. Local Socket Telemetry
EOF

    if [[ -f "$OUT/inventory/sockets.txt" ]]; then
      echo '```text'
      grep -E 'LISTEN' "$OUT/inventory/sockets.txt" | head -n 25 || true
      echo '```'
    else
      echo "*Socket inventory not recorded.*"
    fi

    cat << EOF

---
*ArchNetForensics report compiled successfully. Raw PCAP and log archives available in: \`$OUT\`*
EOF
  } > "$LLM_FILE"

  # Create symlink for LLM_REPORT.md
  ln -sf "GROK_ANALYSIS.md" "$OUT/LLM_REPORT.md"
}

#-------------------------------------------------------------------------------
# TERMINAL SUMMARY
#-------------------------------------------------------------------------------
print_summary() {
  printf "\n${CLR_BOLD}══════════════════════════════════════════════════════════════════════${CLR_RESET}\n"
  printf "  ${CLR_GREEN}ArchNetForensics Execution Complete!${CLR_RESET}\n"
  printf "${CLR_BOLD}══════════════════════════════════════════════════════════════════════${CLR_RESET}\n"
  
  local pcap_size="0B"
  if [[ -d "$OUT/pcap" ]]; then
    pcap_size=$(du -sh "$OUT/pcap" 2>/dev/null | awk '{print $1}')
  fi
  local hosts_count=0
  if [[ -f "$OUT/inventory/ping-sweep.csv" ]]; then
    hosts_count=$(awk -F',' 'NR>1 && $3=="up"{print $2}' "$OUT/inventory/ping-sweep.csv" | sort -u | wc -l)
  fi

  printf "  ${CLR_CYAN}Discovered Active Hosts :${CLR_RESET} %d devices\n" "$hosts_count"
  printf "  ${CLR_CYAN}Raw PCAP Directory      :${CLR_RESET} %s (Size: %s)\n" "$OUT/pcap" "${pcap_size:-0B}"
  printf "  ${CLR_CYAN}Full Artifact Directory :${CLR_RESET} %s\n" "$OUT"
  printf "  ${CLR_GREEN}LLM Analysis Dossier    :${CLR_RESET} ${CLR_BOLD}%s/GROK_ANALYSIS.md${CLR_RESET}\n\n" "$OUT"
  
  printf "${CLR_BOLD}🤖 How to get an instant AI security analysis:${CLR_RESET}\n"
  printf "  1. Open the dossier: ${CLR_CYAN}cat '%s/GROK_ANALYSIS.md'${CLR_RESET}\n" "$OUT"
  printf "  2. Copy and paste the contents into ${CLR_BOLD}Grok, Claude, or ChatGPT${CLR_RESET}.\n"
  printf "  3. The LLM will provide an expert, plain-English security verdict.\n\n"
}

#-------------------------------------------------------------------------------
# LIVE STATUS MONITOR (CLEAN TERMINAL DISPLAY)
#-------------------------------------------------------------------------------
printf "${CLR_CYAN}[*] Forensic probes initialized. Running for %d minutes...${CLR_RESET}\n" "$DURATION_MIN"
printf "${CLR_GRAY}    Press Ctrl+C at any time to conclude early and generate reports.${CLR_RESET}\n\n"

START_SEC=$(date +%s)
TOTAL_SEC=$((DURATION_MIN * 60))

while true; do
  NOW_SEC=$(date +%s)
  ELAPSED=$((NOW_SEC - START_SEC))
  if (( ELAPSED >= TOTAL_SEC )); then
    break
  fi

  REMAINING=$((TOTAL_SEC - ELAPSED))
  ELAPSED_MIN=$((ELAPSED / 60))
  ELAPSED_S=$((ELAPSED % 60))
  REM_MIN=$((REMAINING / 60))
  REM_S=$((REMAINING % 60))

  # Quick telemetry metrics for live display
  hosts_seen=0
  if [[ -f "$OUT/inventory/ping-sweep.csv" ]]; then
    hosts_seen=$(awk -F',' 'NR>1 && $3=="up"{print $2}' "$OUT/inventory/ping-sweep.csv" 2>/dev/null | sort -u | wc -l || echo 0)
  fi
  anoms=0
  if [[ -f "$OUT/reports/anomaly-watch.txt" ]]; then
    anoms=$(grep -cE "ALERT|ANOMALY" "$OUT/reports/anomaly-watch.txt" 2>/dev/null || echo 0)
  fi

  # Active process count
  active_jobs=0
  for pid in "${PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      ((active_jobs++))
    fi
  done

  # Print dynamic progress line (clears line and updates in place)
  printf "\r${CLR_CYAN}[%s]${CLR_RESET} Elapsed: ${CLR_BOLD}%02dm %02ds${CLR_RESET} | Remaining: %02dm %02ds | Probes Active: %d | Hosts Found: %d | Anomalies: %d" \
    "$(date +%H:%M:%S)" "$ELAPSED_MIN" "$ELAPSED_S" "$REM_MIN" "$REM_S" "$active_jobs" "$hosts_seen" "$anoms"

  sleep 5
done

cleanup
