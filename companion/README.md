# Wi-Fi Deauth IDS (defensive)

Receive-only intrusion detection for **deauthentication** and **disassociation** floods — the usual “Wi‑Fi jammer” technique against home networks.

It sniffs a **monitor-mode** interface, counts kill-frames in a sliding window, and **alerts** you (terminal + desktop notification + optional sound + log) when the rate looks like an attack.

This tool **never transmits**. It does not jam, deauth, or attack anyone.

## Requirements

- Linux, root privileges
- A Wi‑Fi adapter that supports **monitor mode** (second USB adapter is ideal so your main connection stays up)
- Python 3.10+
- `scapy`, `iw`, optional `notify-send` / `paplay`

```bash
cd ~/Projects/wifi-deauth-ids
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick start

```bash
# 1) Put spare NIC into monitor mode (example: wlan1 → wlan1mon)
sudo ./setup_monitor.sh wlan1

# 2) Run the IDS (defaults: wlan1mon, ≥15 frames / 10s)
sudo python3 deauth_ids.py -i wlan1mon

# Tuned for a noisy environment (fewer false positives)
sudo python3 deauth_ids.py -i wlan1mon -t 30 -w 5 --hop --channels 1,6,11
```

### Useful flags

| Flag | Meaning |
|------|---------|
| `-i wlan1mon` | Monitor interface |
| `-t 15` | Alert threshold (frames in window) |
| `-w 10` | Window length in seconds |
| `-c 30` | Cooldown between repeated alerts |
| `--hop` | Hop channels (2.4 GHz by default) |
| `--channels 1,6,11` | Only hop common channels |
| `-q` | Quiet — only alerts / status |
| `--no-notify` / `--no-sound` | Disable desktop/sound alerts |
| `-l path` | Log file |

## How detection works

1. Capture 802.11 **deauth** (subtype 12) and **disassoc** (subtype 10) frames.
2. Keep them in a **sliding time window**.
3. If count ≥ **threshold**, fire an alert (with cooldown so you aren’t spammed).
4. Summarize top **source**, **target**, and **BSSID** MACs plus reason codes.

**Important:** Source MACs in deauth frames are often **spoofed** (attacker pretends to be your AP or client). Treat “attacker MAC” as a clue, not proof.

### False positives

Legitimate gear sometimes sends a few deauths (AP reboot, band steering, client roaming). Rate thresholds avoid alerting on one-off frames. Raise `-t` if your AP is chatty.

## Hardening your home network (best defense)

Detection tells you you’re under fire. **Prevention** is better:

1. **Enable Protected Management Frames (PMF / 802.11w)**  
   - On many routers: “Protected Management Frames”, “PMF”, or “802.11w” → **Capable** or **Required**.  
   - **WPA3** typically requires PMF and blocks classic deauth kicks for capable clients.

2. **Prefer WPA3** (or WPA2+WPA3 mixed if older devices need it).

3. **Critical devices on Ethernet** (or powerline) so Wi‑Fi storms don’t kill them.

4. **Keep firmware updated** on the AP; disable WPS if you don’t need it.

5. **Dedicated monitor radio** for this IDS so your laptop can stay associated while watching.

6. If under sustained attack: change channel/band, enable PMF if off, switch important gear to cable, note times for pattern (neighbor? portable attacker?).

## What an alert means for you

| Symptom | Likely cause |
|---------|----------------|
| Devices drop Wi‑Fi repeatedly | Deauth flood on your channel |
| Only some clients affected | Targeted frames to those MACs |
| Alerts + stable ethernet | Air-side only — expected for RF attacks |

During an alert:

1. Note the **BSSID** (should be your AP if you’re the target).
2. Check whether **PMF** is on.
3. Move phone/laptop to **5 GHz** or **ethernet** if available.
4. Log time + summary from `deauth_ids.log` if you need evidence later.

## Legal / ethics

Use only on networks and spectrum you are allowed to monitor (your home, your lab). Monitor mode captures nearby frames; be mindful of local privacy law. Do **not** use capture data to attack others.

## Files

- `deauth_ids.py` — main IDS
- `setup_monitor.sh` — helper to enable monitor mode
- `requirements.txt` — Python deps
- `deauth_ids.log` — created when you run with default `-l`
