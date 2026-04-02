#!/usr/bin/env python3
"""
network_sniffer.py — Basic Network Packet Sniffer
Personal Cybersecurity Project
Author: Adithyan V

Captures live network traffic and displays:
  - Timestamp
  - Protocol (TCP / UDP / ICMP)
  - Source and Destination IPs
  - Ports and TCP Flags
  - Payload preview (first 50 bytes)

Run as root: sudo python3 network_sniffer.py
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from scapy.arch import get_if_list
from datetime import datetime
import sys

# ─── Config ────────────────────────────────────────────────────────────────
PACKET_COUNT = 0      # 0 = capture indefinitely until Ctrl+C
SHOW_PAYLOAD = True   # Show raw payload preview

# ─── Counters ──────────────────────────────────────────────────────────────
stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0, "TOTAL": 0}

# ─── Packet Handler ─────────────────────────────────────────────────────────
def process_packet(packet):
    stats["TOTAL"] += 1
    timestamp = datetime.now().strftime("%H:%M:%S")

    # Only process IP packets
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = ""
    info = ""

    # ── TCP ──
    if packet.haslayer(TCP):
        protocol = "TCP"
        stats["TCP"] += 1
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags    = packet[TCP].flags
        # Decode common flag combos
        flag_str = str(flags)
        info = f"Ports: {src_port} → {dst_port} | Flags: {flag_str}"

    # ── UDP ──
    elif packet.haslayer(UDP):
        protocol = "UDP"
        stats["UDP"] += 1
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        info = f"Ports: {src_port} → {dst_port}"

    # ── ICMP ──
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        stats["ICMP"] += 1
        icmp_type = packet[ICMP].type
        type_str  = "request" if icmp_type == 8 else "reply" if icmp_type == 0 else str(icmp_type)
        info = f"Type: {icmp_type} ({type_str})"

    # ── Other ──
    else:
        protocol = "OTHER"
        stats["OTHER"] += 1
        info = f"Proto ID: {packet[IP].proto}"

    # ── Payload Preview ──
    payload_preview = ""
    if SHOW_PAYLOAD and packet.haslayer(Raw):
        raw = packet[Raw].load
        try:
            decoded = raw[:50].decode("utf-8", errors="replace").replace("\n", " ").replace("\r", "")
            payload_preview = f" | Payload: {decoded}"
        except Exception:
            payload_preview = f" | Payload (hex): {raw[:50].hex()}"

    # ── Print ──
    print(
        f"[{timestamp}] {protocol:<5} | "
        f"{src_ip:<15} → {dst_ip:<15} | "
        f"{info}{payload_preview}"
    )


# ─── Summary on Exit ────────────────────────────────────────────────────────
def print_summary():
    print("\n" + "=" * 65)
    print("  📊 Capture Summary")
    print("=" * 65)
    print(f"  Total Packets : {stats['TOTAL']}")
    print(f"  TCP           : {stats['TCP']}")
    print(f"  UDP           : {stats['UDP']}")
    print(f"  ICMP          : {stats['ICMP']}")
    print(f"  Other         : {stats['OTHER']}")
    print("=" * 65)


# ─── Main ───────────────────────────────────────────────────────────────────
def main():
    print("=" * 65)
    print("        🔍 Basic Network Sniffer — Personal Cybersecurity Project")
    print("             Project | Author: Adithyan V")
    print("=" * 65)
    print("⚠️  Run as root/sudo on Kali Linux")
    print(f"📡 Capturing live packets... Press Ctrl+C to stop.\n")
    print(
        f"{'Time':<10} {'Proto':<6} {'Source IP':<17}"
        f"{'Destination IP':<17} {'Info'}"
    )
    print("─" * 65)

    try:
        # Auto-detect interfaces
        available = get_if_list()
        ifaces = [
            i for i in available
            if i == "lo"
            or i.startswith("wl")
            or i.startswith("en")
            or i.startswith("eth")
        ]
        if not ifaces:
            ifaces = available

        sniff(
            prn=process_packet,
            store=False,
            count=PACKET_COUNT,
            iface=ifaces,
        )

    except KeyboardInterrupt:
        print_summary()
        sys.exit(0)


if __name__ == "__main__":
    main()
