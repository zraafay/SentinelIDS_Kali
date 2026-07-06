#!/bin/bash
# Install system-level dependencies required for NetfilterQueue and PyQt5 on Kali Linux
echo "[*] Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y python3-pyqt5 libnetfilter-queue-dev iptables build-essential python3-dev

# Install Python requirements
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

# Configure iptables for the IPS Engine
# This redirects all incoming, outgoing, and forwarded IP packets to NetfilterQueue #1
echo "[*] Setting up iptables rules for NetfilterQueue (Queue 1)..."
sudo iptables -I INPUT -j NFQUEUE --queue-num 1
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1
sudo iptables -I FORWARD -j NFQUEUE --queue-num 1

echo "[+] Setup complete! To revert iptables later, run: sudo iptables -F"