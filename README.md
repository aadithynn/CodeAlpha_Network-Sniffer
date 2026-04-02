# 🔍 Basic Network Sniffer
  
**Author:** Adithyan V  
**Language:** Python 3 | **Library:** Scapy

---

## 📌 Overview

A custom-built **Network Packet Sniffer** that captures and analyzes live network traffic in real time. Built with Python and Scapy as part of the Personal Cybersecurity Project. Displays source/destination IPs, protocols, ports, and payload previews for every captured packet.

---

## 🔍 What It Captures & Analyzes

| Protocol | Info Displayed |
|---|---|
| TCP | Source/Destination IP, Ports, TCP Flags |
| UDP | Source/Destination IP, Ports |
| ICMP | Source/Destination IP, ICMP Type (ping/reply) |
| Other | Protocol ID |
| All | Raw payload preview (first 50 bytes) |

---

## 📁 Project Structure

```
network_sniffer/
├── network_sniffer.py   # Main sniffer — captures and analyzes packets
└── README.md
```

---

## ⚙️ Setup & Installation

### Prerequisites
```bash
# Kali Linux (recommended) or any Linux distro
sudo apt update
sudo apt install python3 python3-pip -y
pip install scapy
```

### Run
```bash
git clone https://github.com/aadithynn/Network-Sniffer
cd Network-Sniffer

# Must run as root to capture packets
sudo python3 network_sniffer.py
```

---

## 🖥️ Sample Output

```
======================================================================
        🔍 Basic Network Sniffer — Personal Cybersecurity Project
======================================================================
⚠️  Run as root/sudo on Kali Linux
📡 Capturing live packets... Press Ctrl+C to stop.

[14:32:01] TCP   | 192.168.1.5     → 142.250.77.46  | Ports: 54231 → 443 | Flags: PA
[14:32:01] UDP   | 192.168.1.1     → 192.168.1.5    | Ports: 53 → 45231
[14:32:02] ICMP  | 192.168.1.5     → 8.8.8.8        | Type: 8 (0=reply, 8=request)
[14:32:03] TCP   | 192.168.1.5     → 142.250.77.46  | Ports: 54231 → 443 | Flags: PA | Payload: GET / HTTP/1.1
```

---

## 🧠 How It Works

```
Network Interface (promiscuous mode)
        │
        ▼
   Scapy Sniffer
        │
        ├──► IP Layer  →  Extract src/dst IP
        ├──► TCP Layer →  Extract ports + flags
        ├──► UDP Layer →  Extract ports
        ├──► ICMP Layer → Extract type (ping/reply)
        └──► Raw Layer →  Preview payload (50 bytes)
                │
                ▼
        Console Output (timestamped)
```

---

## 📖 Key Concepts Demonstrated

- **Packet Capture** — How Scapy puts the NIC into promiscuous mode to intercept all traffic
- **Protocol Analysis** — Difference between TCP (reliable), UDP (fast), ICMP (diagnostic)
- **Packet Structure** — How each packet has layers (Ethernet → IP → TCP/UDP → Payload)
- **Network Forensics** — Reading source/destination IPs and ports to understand data flow

---

## ⚠️ Legal Disclaimer

This tool is built for **educational purposes** as a personal cybersecurity project.  
Only use on networks you own or have explicit permission to monitor.  
Unauthorized packet sniffing is illegal in most jurisdictions.

---

## 🏷️ Tools & References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Wireshark — Packet Analysis Reference](https://www.wireshark.org/)
- [TCP/IP Protocol Suite](https://en.wikipedia.org/wiki/Internet_protocol_suite)
- Personal Cybersecurity Project Program
