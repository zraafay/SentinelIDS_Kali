# SentinelIDS - Kali Linux Edition

SentinelIDS is an advanced local Network Packet Analyzer and Intrusion Detection/Prevention System (IDS/IPS) built in Python. Designed specifically for Kali Linux, it provides real-time traffic monitoring, stateful forensic analysis, and active threat mitigation using NetfilterQueue and Scapy.

## Features

* **Live Packet Sniffing:** Captures network traffic in real-time using raw sockets.
* **Stateful TCP/UDP Analysis:** Detects stealth scans (Xmas, NULL), SYN floods, and abnormal port activity.
* **Layer 2/3 Threat Detection:** Identifies ARP spoofing/poisoning and monitors for blacklisted IP addresses.
* **Deep Packet Inspection (DPI):** Analyzes payload bytes for cleartext credentials (FTP/Telnet/HTTP Basic) and malicious patterns (SQLi, XSS).
* **Active Intrusion Prevention:** Integrates with Linux `iptables` and `NetfilterQueue` to actively drop malicious packets.
* **Interactive GUI:** Provides a responsive, dark-themed dashboard built with PyQt5 for live traffic monitoring, threat alerts, manual filtering, and detailed packet inspection.

## Project Structure

* `main.py`: The entry point for the PyQt5 graphical interface and application state.
* `core/`
  * `analyzer.py`: The core IDS engine handling deep packet inspection, signature matching, and stateful tracking.
  * `ips_engine.py`: Manages the NetfilterQueue integration for active packet blocking and forwarding.
  * `sniffer.py`: Handles passive packet capture and PCAP data management.
* `config/`
  * `blacklist.txt`: Local threat intelligence list of IPs to automatically drop.
  * `whitelist.txt`: Trusted IPs that bypass the IDS engine.
* `setup_network.sh`: Bash script to install system dependencies and configure `iptables` routing rules.
* `requirements.txt`: Python package dependencies.

## Prerequisites

This tool is designed specifically for **Kali Linux** and requires **root (sudo) privileges** to manipulate `iptables` and capture packets via raw sockets.

## Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/yourusername/SentinelIPS.git](https://github.com/yourusername/SentinelIPS.git)
   cd SentinelIPS/SentinelIPS_Kali
