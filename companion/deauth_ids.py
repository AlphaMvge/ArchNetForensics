#!/usr/bin/env python3
"""
Wi-Fi Deauth / Disassoc IDS — defensive monitor only.

Sniffs 802.11 management frames on a monitor-mode interface and alerts when
deauthentication or disassociation traffic looks like an active attack
(rate-based thresholds, not single legitimate frames).

Requires root and a monitor-mode interface (e.g. wlan1mon).
Does not transmit frames.
"""

from __future__ import annotations

import argparse
import collections
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Deque, Dict, Optional, Tuple

try:
    from scapy.all import (  # type: ignore
        Dot11,
        Dot11Deauth,
        Dot11Disas,
        RadioTap,
        sniff,
    )
except ImportError:
    print("scapy is required: pip install scapy", file=sys.stderr)
    sys.exit(1)


# 802.11 reason codes commonly seen in deauth floods
REASON_NAMES = {
    1: "unspecified",
    2: "prev_auth_invalid",
    3: "deauth_leaving",
    4: "inactivity",
    5: "ap_unable",
    6: "class2_from_nonauth",
    7: "class3_from_nonassoc",
    8: "disassoc_leaving",
    9: "assoc_not_auth",
}


@dataclass
class Config:
    interface: str = "wlan1mon"
    window_sec: float = 10.0
    threshold: int = 15          # frames in window → alert
    alert_cooldown: float = 30.0
    channel_hop: bool = False
    hop_interval: float = 0.5
    channels: Tuple[int, ...] = tuple(range(1, 12))  # 2.4 GHz default
    log_file: Optional[Path] = None
    notify: bool = True
    sound: bool = True
    quiet: bool = False
    bpf: Optional[str] = None    # optional BPF (rarely useful for mgmt)


@dataclass
class FrameEvent:
    ts: float
    kind: str  # "deauth" | "disassoc"
    src: str
    dst: str
    bssid: str
    reason: int
    channel: Optional[int] = None


@dataclass
class DetectorState:
    events: Deque[FrameEvent] = field(default_factory=collections.deque)
    last_alert: float = 0.0
    total_deauth: int = 0
    total_disassoc: int = 0
    alerts_fired: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


class Colors:
    RED = "\033[91m"
    YEL = "\033[93m"
    GRN = "\033[92m"
    CYN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RST = "\033[0m"


def mac(addr) -> str:
    if addr is None:
        return "??:??:??:??:??:??"
    return str(addr).lower()


def reason_str(code: int) -> str:
    name = REASON_NAMES.get(code, "other")
    return f"{code} ({name})"


def desktop_notify(title: str, body: str) -> None:
    try:
        subprocess.run(
            ["notify-send", "-u", "critical", "-a", "WiFi Deauth IDS", title, body],
            check=False,
            timeout=5,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass


def play_alert_sound() -> None:
    # Prefer a short system sound; fall back to terminal bell.
    candidates = [
        "/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga",
        "/usr/share/sounds/freedesktop/stereo/dialog-warning.oga",
        "/usr/share/sounds/freedesktop/stereo/complete.oga",
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                subprocess.Popen(
                    ["paplay", path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return
            except (FileNotFoundError, OSError):
                break
    try:
        sys.stdout.write("\a")
        sys.stdout.flush()
    except OSError:
        pass


def set_channel(iface: str, channel: int) -> None:
    try:
        subprocess.run(
            ["iw", "dev", iface, "set", "channel", str(channel)],
            check=False,
            timeout=2,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass


def channel_hopper(iface: str, channels: Tuple[int, ...], interval: float, stop: threading.Event) -> None:
    idx = 0
    while not stop.is_set():
        set_channel(iface, channels[idx % len(channels)])
        idx += 1
        stop.wait(interval)


def extract_radiotap_channel(pkt) -> Optional[int]:
    """Best-effort channel from RadioTap if present."""
    try:
        if pkt.haslayer(RadioTap):
            rt = pkt[RadioTap]
            # ChannelFreq is common; convert MHz → approx channel for 2.4 GHz
            freq = getattr(rt, "ChannelFrequency", None) or getattr(rt, "ChannelFreq", None)
            if freq:
                if 2412 <= freq <= 2484:
                    return (freq - 2412) // 5 + 1
                if 5000 <= freq <= 5900:
                    return (freq - 5000) // 5
    except Exception:
        pass
    return None


def build_alert_summary(events: list[FrameEvent], window: float) -> str:
    by_src: Dict[str, int] = collections.Counter()
    by_dst: Dict[str, int] = collections.Counter()
    by_bssid: Dict[str, int] = collections.Counter()
    by_kind: Dict[str, int] = collections.Counter()
    reasons: Dict[int, int] = collections.Counter()

    for e in events:
        by_src[e.src] += 1
        by_dst[e.dst] += 1
        by_bssid[e.bssid] += 1
        by_kind[e.kind] += 1
        reasons[e.reason] += 1

    top_src = by_src.most_common(3)
    top_dst = by_dst.most_common(3)
    top_bssid = by_bssid.most_common(3)
    top_reason = reasons.most_common(3)

    lines = [
        f"{len(events)} management kill-frames in {window:.0f}s window",
        f"  kinds: " + ", ".join(f"{k}={v}" for k, v in by_kind.items()),
        f"  top sources (possible attacker spoof/real):",
    ]
    for addr, n in top_src:
        lines.append(f"    {addr}  ×{n}")
    lines.append("  top targets (victims):")
    for addr, n in top_dst:
        lines.append(f"    {addr}  ×{n}")
    lines.append("  BSSIDs involved:")
    for addr, n in top_bssid:
        lines.append(f"    {addr}  ×{n}")
    lines.append("  reason codes:")
    for code, n in top_reason:
        lines.append(f"    {reason_str(code)}  ×{n}")
    return "\n".join(lines)


class DeauthIDS:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.state = DetectorState()
        self.stop = threading.Event()
        self.logger = logging.getLogger("deauth_ids")
        self._setup_logging()

    def _setup_logging(self) -> None:
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()
        fmt = logging.Formatter("%(asctime)s  %(levelname)s  %(message)s", "%Y-%m-%d %H:%M:%S")
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        self.logger.addHandler(sh)
        if self.cfg.log_file:
            self.cfg.log_file.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(self.cfg.log_file)
            fh.setFormatter(fmt)
            self.logger.addHandler(fh)

    def _prune(self, now: float) -> None:
        cutoff = now - self.cfg.window_sec
        while self.state.events and self.state.events[0].ts < cutoff:
            self.state.events.popleft()

    def handle_packet(self, pkt) -> None:
        if not pkt.haslayer(Dot11):
            return

        kind = None
        reason = 0
        if pkt.haslayer(Dot11Deauth):
            kind = "deauth"
            reason = int(pkt[Dot11Deauth].reason)
        elif pkt.haslayer(Dot11Disas):
            kind = "disassoc"
            reason = int(pkt[Dot11Disas].reason)
        else:
            return

        d11 = pkt[Dot11]
        # addr2 = transmitter, addr1 = receiver, addr3 = BSSID (typical for mgmt)
        event = FrameEvent(
            ts=time.time(),
            kind=kind,
            src=mac(d11.addr2),
            dst=mac(d11.addr1),
            bssid=mac(d11.addr3),
            reason=reason,
            channel=extract_radiotap_channel(pkt),
        )

        with self.state.lock:
            if kind == "deauth":
                self.state.total_deauth += 1
            else:
                self.state.total_disassoc += 1

            self.state.events.append(event)
            self._prune(event.ts)
            count = len(self.state.events)
            snapshot = list(self.state.events)

            if not self.cfg.quiet:
                ch = f" ch{event.channel}" if event.channel else ""
                print(
                    f"{Colors.DIM}{datetime.now().strftime('%H:%M:%S')}{Colors.RST} "
                    f"{Colors.YEL}{event.kind:8}{Colors.RST} "
                    f"src={event.src}  dst={event.dst}  bssid={event.bssid}  "
                    f"reason={reason_str(event.reason)}{ch}  "
                    f"[{count}/{self.cfg.threshold} in {self.cfg.window_sec:.0f}s]"
                )

            if count >= self.cfg.threshold:
                now = event.ts
                if now - self.state.last_alert >= self.cfg.alert_cooldown:
                    self.state.last_alert = now
                    self.state.alerts_fired += 1
                    self._fire_alert(snapshot)

    def _fire_alert(self, events: list[FrameEvent]) -> None:
        summary = build_alert_summary(events, self.cfg.window_sec)
        banner = (
            f"\n{Colors.RED}{Colors.BOLD}"
            f"{'=' * 60}\n"
            f"  ALERT: possible deauth / disassoc attack\n"
            f"{'=' * 60}{Colors.RST}\n"
            f"{summary}\n"
            f"{Colors.CYN}Mitigations: enable 802.11w/PMF (or WPA3), "
            f"move critical devices to ethernet, "
            f"note attacker MACs may be spoofed.{Colors.RST}\n"
        )
        print(banner)
        self.logger.warning("DEAUTH ATTACK LIKELY\n%s", summary)

        short = (
            f"{len(events)} deauth/disassoc frames in "
            f"{self.cfg.window_sec:.0f}s — check Wi-Fi stability"
        )
        if self.cfg.notify:
            desktop_notify("Wi-Fi attack suspected", short)
        if self.cfg.sound:
            play_alert_sound()

    def status_loop(self) -> None:
        while not self.stop.wait(30.0):
            with self.state.lock:
                self._prune(time.time())
                n = len(self.state.events)
                d, s, a = self.state.total_deauth, self.state.total_disassoc, self.state.alerts_fired
            print(
                f"{Colors.GRN}[status]{Colors.RST} window={n}  "
                f"lifetime deauth={d} disassoc={s}  alerts={a}"
            )

    def run(self) -> None:
        if os.geteuid() != 0:
            self.logger.error("Root required for monitor-mode capture (try sudo).")
            sys.exit(1)

        hop_thread = None
        if self.cfg.channel_hop:
            hop_thread = threading.Thread(
                target=channel_hopper,
                args=(self.cfg.interface, self.cfg.channels, self.cfg.hop_interval, self.stop),
                daemon=True,
            )
            hop_thread.start()
            self.logger.info(
                "Channel hopping on %s every %.1fs across %s",
                self.cfg.interface,
                self.cfg.hop_interval,
                list(self.cfg.channels),
            )

        status = threading.Thread(target=self.status_loop, daemon=True)
        status.start()

        self.logger.info(
            "Listening on %s — alert if ≥%d deauth/disassoc in %.0fs (cooldown %.0fs)",
            self.cfg.interface,
            self.cfg.threshold,
            self.cfg.window_sec,
            self.cfg.alert_cooldown,
        )
        self.logger.info("Ctrl+C to stop. This tool only receives frames; it never jams.")

        def _sig(_signum, _frame):
            self.stop.set()
            raise KeyboardInterrupt

        signal.signal(signal.SIGINT, _sig)
        signal.signal(signal.SIGTERM, _sig)

        try:
            sniff(
                iface=self.cfg.interface,
                prn=self.handle_packet,
                store=False,
                # subtype 10=disassoc, 12=deauth — still filter in callback for safety
                lfilter=lambda p: p.haslayer(Dot11Deauth) or p.haslayer(Dot11Disas),
                stop_filter=lambda _: self.stop.is_set(),
            )
        except PermissionError:
            self.logger.error("Permission denied on %s — need root / CAP_NET_RAW.", self.cfg.interface)
            sys.exit(1)
        except OSError as exc:
            self.logger.error("Interface error on %s: %s", self.cfg.interface, exc)
            self.logger.error(
                "Put the card in monitor mode first, e.g.:\n"
                "  sudo ip link set wlan1 down\n"
                "  sudo iw dev wlan1 set type monitor\n"
                "  sudo ip link set wlan1 up\n"
                "  # or: sudo airmon-ng start wlan1"
            )
            sys.exit(1)
        finally:
            self.stop.set()
            with self.state.lock:
                d, s, a = self.state.total_deauth, self.state.total_disassoc, self.state.alerts_fired
            self.logger.info("Stopped. totals: deauth=%d disassoc=%d alerts=%d", d, s, a)


def parse_args(argv: Optional[list[str]] = None) -> Config:
    p = argparse.ArgumentParser(
        description="Defensive Wi-Fi IDS: alert on deauth/disassoc floods (monitor mode).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-i", "--interface", default="wlan1mon", help="Monitor-mode interface")
    p.add_argument(
        "-w", "--window", type=float, default=10.0, help="Sliding window seconds"
    )
    p.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=15,
        help="Frames in window that trigger an alert",
    )
    p.add_argument(
        "-c",
        "--cooldown",
        type=float,
        default=30.0,
        help="Minimum seconds between repeated alerts",
    )
    p.add_argument(
        "--hop",
        action="store_true",
        help="Hop 2.4 GHz channels (may miss short bursts on one channel)",
    )
    p.add_argument(
        "--channels",
        default="1-11",
        help="Channel list or range for --hop (e.g. 1,6,11 or 1-11)",
    )
    p.add_argument(
        "--hop-interval",
        type=float,
        default=0.5,
        help="Seconds per channel when hopping",
    )
    p.add_argument(
        "-l",
        "--log",
        default=str(Path.home() / "Documents" / "wifi-deauth-ids" / "deauth_ids.log"),
        help="Alert log file path",
    )
    p.add_argument("--no-notify", action="store_true", help="Disable desktop notifications")
    p.add_argument("--no-sound", action="store_true", help="Disable alert sound")
    p.add_argument("-q", "--quiet", action="store_true", help="Only print alerts/status")
    args = p.parse_args(argv)

    channels: list[int] = []
    for part in args.channels.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            channels.extend(range(int(a), int(b) + 1))
        elif part:
            channels.append(int(part))
    if not channels:
        channels = list(range(1, 12))

    return Config(
        interface=args.interface,
        window_sec=args.window,
        threshold=args.threshold,
        alert_cooldown=args.cooldown,
        channel_hop=args.hop,
        hop_interval=args.hop_interval,
        channels=tuple(channels),
        log_file=Path(args.log) if args.log else None,
        notify=not args.no_notify,
        sound=not args.no_sound,
        quiet=args.quiet,
    )


def main() -> None:
    cfg = parse_args()
    DeauthIDS(cfg).run()


if __name__ == "__main__":
    main()
