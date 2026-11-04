# 🤖 LLM & Grok Analysis Guide — ArchNetForensics

ArchNetForensics automatically condenses thousands of network packets, socket tables, ARP inventories, and anomaly flags into an **LLM-optimized briefing dossier** saved as:
```
<output_dir>/GROK_ANALYSIS.md
```
*(also symlinked as `<output_dir>/LLM_REPORT.md`)*

---

## 🎯 Why LLM-Ready Reporting?

Raw network forensics outputs (such as multi-gigabyte PCAPs, raw `nmap` traces, and `ss` socket tables) are overwhelming for average users and small business administrators. 

ArchNetForensics bridges this gap by:
1. **Preserving 100% of raw evidence**: Full rotating PCAPs, IoT chatter dumps, and logs are safely stored on disk.
2. **Synthesizing Crucial Telemetry**: Extracts active IP/MAC addresses, vendor tags, open high-risk ports, duplicate MAC alerts (ARP spoofing), and SYN floods.
3. **Embedding an Executive System Prompt**: Pre-formats the file so you can copy and paste directly into Grok, Claude, or ChatGPT to get an immediate plain-English verdict.

---

## 🚀 How to Use with Grok (or any LLM)

### Step 1: Run ArchNetForensics
```bash
sudo ./archnetforensics.sh -d 15
```

### Step 2: Open the Generated Dossier
When the run finishes (or when you press `Ctrl+C`), notice the final summary output:
```bash
cat archnet-forensics-YYYYMMDD-HHMMSS/GROK_ANALYSIS.md
```
Or copy it to your clipboard:
```bash
# Using xclip on Arch:
xclip -selection clipboard < archnet-forensics-*/GROK_ANALYSIS.md
# Or using wl-copy on Wayland:
wl-copy < archnet-forensics-*/GROK_ANALYSIS.md
```

### Step 3: Paste into Grok
Paste the file directly into [Grok](https://x.ai) or attach `GROK_ANALYSIS.md`.

Grok will automatically read the included system prompt and deliver:
- ✅ **Executive Health Verdict**: Clear green/yellow/red status of your local network.
- 🔍 **Rogue Device Audit**: Identification of any unexpected hardware, rogue APs, or unmapped MACs.
- ⚠️ **Vulnerability Highlights**: Plain-English explanations of open ports like SMB (445), Telnet (23), or industrial protocols (Modbus 502).
- 🛡️ **Actionable Checklist**: Step-by-step guidance on how to fix issues (e.g. disabling UPnP, kicking unknown devices from Wi-Fi router).

---

## 💡 Example Grok Follow-Up Questions
Once Grok analyzes your `GROK_ANALYSIS.md`, you can ask:
- *"Are any of the discovered IoT devices known for security vulnerabilities?"*
- *"Is the DNS traffic showing signs of malware beaconing or data exfiltration?"*
- *"How do I isolate IP 192.168.1.145 on my home router?"*

