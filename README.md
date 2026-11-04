# 🛡️ ArchNetForensics

[![Arch Linux](https://img.shields.io/badge/Arch_Linux-1793D1?logo=arch-linux&logoColor=fff&style=flat-square)](https://archlinux.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Language-Bash%20%7C%20Python3-blue.svg?style=flat-square)](https://www.gnu.org/software/bash/)
[![AI Ready](https://img.shields.io/badge/AI_Ready-Grok%20%7C%20Claude%20%7C%20GPT-purple.svg?style=flat-square)](docs/GROK_LLM_GUIDE.md)

**ArchNetForensics** is a persistent, high-fidelity network diagnostic, anomaly-capture, and forensic telemetry suite built natively for **Arch Linux**. It combines enterprise-grade packet capture and probe routines with automated **LLM-optimized synthesis** (`GROK_ANALYSIS.md`), enabling both security engineers and everyday users to audit network security in plain English.

Includes **Wi-Fi Deauth IDS** as a companion defensive monitor against 802.11 deauthentication and disassociation floods.

---

## 🌟 Key Features

- **🐧 Native Arch Linux Integration (`pacman`)**:
  - Automatically identifies missing tools on startup (`tcpdump`, `nmap`, `traceroute`, `mtr`, `arp-scan`, `iftop`, `vnstat`, etc.).
  - Offers an interactive prompt to install all missing dependencies via `pacman`, selectively choose packages, or gracefully skip missing probes without crashing.
- **🛡️ Multi-Vector Diagnostic & Threat Capture**:
  - **Packet Ring Buffers**: Full rotating captures, IoT discovery chatter (mDNS, SSDP, LLMNR, NetBIOS), and live DNS queries via `tcpdump`.
  - **Continuous Subnet Sweeps**: Rolling ping and latency baselining across internal subnets.
  - **Hardware Discovery**: ARP sweeps and vendor OUI mapping.
  - **Port & Service Fingerprinting**: Nmap top-port sweeps, OS detection, and key service versions.
  - **Live Anomaly Sentinel**: Detects duplicate MAC address spoofing, SYN backlog floods, and broken neighbor states.
- **🤖 LLM-Ready Ingestion (`GROK_ANALYSIS.md`)**:
  - Zero information loss: raw PCAPs, CSVs, and logs are preserved on disk.
  - Automatically distills key findings into a structured briefing file with an embedded SOC analyst prompt ready to paste directly into **Grok**, **Claude**, or **ChatGPT**.
- **📡 Companion Wi-Fi Deauth IDS**:
  - Monitor-mode defensive monitor that sniffs 802.11 management frames and alerts when deauth floods (Wi-Fi jammers) occur.

---

## 📦 Directory Structure

```text
ArchNetForensics/
├── bin/
│   ├── archnetforensics.sh       # Main forensics & anomaly detection engine
├── companion/
│   ├── deauth_ids.py             # Companion 802.11 Deauth/Disassoc IDS
│   ├── setup_monitor.sh          # Helper to initialize monitor-mode NIC
│   ├── requirements.txt          # Python requirements (scapy)
│   └── README.md                 # Companion documentation
├── docs/
│   └── GROK_LLM_GUIDE.md         # Guide for Grok & AI analysis
├── install.sh                    # System installer (/usr/local/bin)
├── uninstall.sh                  # Clean uninstaller
├── LICENSE                       # MIT License
└── README.md
```

---

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/AlphaMvge/ArchNetForensics.git
cd ArchNetForensics
```

### 2. Run the Suite
You can run it directly:
```bash
sudo ./archnetforensics.sh
```
Or install it system-wide to `/usr/local/bin`:
```bash
sudo ./install.sh
sudo archnetforensics
```

---

## ⚙️ Interactive Arch Dependency Manager

When running for the first time, `archnetforensics` verifies system dependencies:

```text
[!] Dependency Check: 3 tool(s) missing on your system:
    • arp-scan     (Arch pacman package: arp-scan)
    • mtr          (Arch pacman package: mtr)
    • iftop        (Arch pacman package: iftop)

How would you like to handle missing dependencies?
  [1] Install ALL missing packages via pacman (Recommended)
  [2] Selectively prompt for each tool
  [3] Skip missing tools and continue running with available probes
Enter choice [1-3] (default: 1):
```

### Non-Interactive Automation Flags
For scripted runs or headless systems:
- **Auto-install all missing packages**:
  ```bash
  sudo ./archnetforensics.sh -y
  ```
- **Skip missing tools without prompting**:
  ```bash
  sudo ./archnetforensics.sh --skip-missing
  ```

---

## 🔧 CLI Flags & Options

```text
Usage: sudo ./archnetforensics.sh [OPTIONS] [duration_minutes] [output_dir]

Options:
  -d, --duration <min>    Run duration in minutes (default: 15)
  -o, --output <dir>      Custom output directory for artifacts
  -i, --iface <interface> Override primary capture interface (default: default route interface)
  -s, --subnet <cidr>     Override scan subnet (default: auto-detected /24)
  -y, --install-all       Non-interactive: auto-install all missing Arch packages
      --skip-missing      Non-interactive: skip all missing tools without prompting
  -f, --filter <bpf>      Optional BPF filter for packet captures (e.g., 'not port 22')
      --wifi-ids          Launch companion Wi-Fi Deauth IDS monitor
  -v, --version           Show version
  -h, --help              Show help menu
```

---

## 🤖 Analyzing Output with Grok (or AI)

When the suite finishes (or when you press `Ctrl+C` to conclude early), it generates:
```text
<output_dir>/GROK_ANALYSIS.md
```

Simply copy the content of this file and paste it into **Grok**:
```bash
cat archnet-forensics-*/GROK_ANALYSIS.md | xclip -selection clipboard
```

Grok will immediately process the telemetry and provide:
1. **Executive Health Verdict**: Clear summary of your network's security posture.
2. **Device & Rogue Audit**: Flagging of unknown hardware or anomalous MACs.
3. **Open Port Risk Rating**: Identification of dangerous services (e.g. Telnet, unencrypted HTTP, SMB).
4. **Actionable Remediation**: Straightforward steps for an everyday user to lock down their network.

For more details, see the [Grok & LLM Analysis Guide](docs/GROK_LLM_GUIDE.md).

---

## 📡 Companion Tool: Wi-Fi Deauth IDS

ArchNetForensics includes a dedicated defensive IDS monitor for wireless networks:
```bash
# 1) Put secondary Wi-Fi adapter into monitor mode
sudo ./companion/setup_monitor.sh wlan1

# 2) Run the defensive IDS
sudo python3 companion/deauth_ids.py -i wlan1mon

# Or launch directly via wrapper:
sudo ./archnetforensics.sh --wifi-ids -i wlan1mon
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) © 2026 AlphaMvge.

