import time
import re
from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, Raw

class PacketAnalyzer:
    def __init__(self):
        # Stateful Tracking Structures
        self.arp_table = {}          # Maps IP -> MAC to detect ARP spoofing
        self.syn_tracker = {}        # Tracks incomplete TCP handshakes (SYN floods)
        self.packet_counts = {}      # IP -> Count for rate monitoring/top talkers
        self.port_scan_tracker = {}  # IP -> Set of scanned ports
        
        # Load Local Threat Intel
        self.blacklist = self._load_list("config/blacklist.txt")
        self.whitelist = self._load_list("config/whitelist.txt")

    def _load_list(self, filepath):
        try:
            with open(filepath, 'r') as f:
                return {line.strip() for line in f if line.strip() and not line.startswith('#')}
        except FileNotFoundError:
            return set()

    def analyze_packet(self, packet):
        """
        Main inspection pipeline. Extracts metadata, decodes payload, and runs IDS rules.
        Returns a dictionary of packet metadata and any generated alerts.
        """
        meta = {
            "timestamp": time.time(),
            "length": len(packet),
            "src_ip": None, "dst_ip": None,
            "src_mac": None, "dst_mac": None,
            "protocol": "Unknown",
            "src_port": None, "dst_port": None,
            "tcp_flags": None,
            "payload_hex": "",
            "payload_ascii": "",
            "alerts": []
        }

        # 1. Layer 2 Analysis (Ethernet / ARP)
        if packet.haslayer(Ether):
            meta["src_mac"] = packet[Ether].src
            meta["dst_mac"] = packet[Ether].dst

        if packet.haslayer(ARP):
            meta["protocol"] = "ARP"
            self._check_arp_spoofing(packet, meta)

        # 2. Layer 3 Analysis (IP)
        if packet.haslayer(IP):
            meta["src_ip"] = packet[IP].src
            meta["dst_ip"] = packet[IP].dst
            
            # Rate tracking for Top Talkers
            self.packet_counts[meta["src_ip"]] = self.packet_counts.get(meta["src_ip"], 0) + 1

            # Check Blacklist
            if meta["src_ip"] in self.blacklist:
                meta["alerts"].append("Blacklisted IP detected in source.")

        # 3. Layer 4 Analysis (TCP / UDP / ICMP)
        if packet.haslayer(TCP):
            meta["protocol"] = "TCP"
            meta["src_port"] = packet[TCP].sport
            meta["dst_port"] = packet[TCP].dport
            meta["tcp_flags"] = packet[TCP].flags
            self._analyze_tcp(packet, meta)

        elif packet.haslayer(UDP):
            meta["protocol"] = "UDP"
            meta["src_port"] = packet[UDP].sport
            meta["dst_port"] = packet[UDP].dport
            self._analyze_udp(packet, meta)

        elif packet.haslayer(ICMP):
            meta["protocol"] = "ICMP"

        # 4. Payload Extraction (Byte-level Forensics)
        if packet.haslayer(Raw):
            raw_bytes = packet[Raw].load
            meta["payload_hex"] = raw_bytes.hex()
            # Decode ASCII, ignoring non-printable chars for safe viewing
            meta["payload_ascii"] = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw_bytes)
            self._analyze_payload(raw_bytes, meta)

        return meta

    def _analyze_tcp(self, packet, meta):
        """Forensic analysis of TCP headers for stealth scans and state anomalies."""
        flags = meta["tcp_flags"]
        src_ip = meta["src_ip"]

        # Xmas Scan Detection: FIN, PSH, URG flags set (Value 41 / 0x29)
        # Attackers use this to light up a packet "like a Christmas tree" to bypass stateless firewalls
        if flags == 0x29 or flags == "FPU":
            meta["alerts"].append("XMAS Scan Detected: FIN, PSH, URG flags set. Indicates OS fingerprinting or firewall evasion.")

        # NULL Scan Detection: No flags set (Value 0)
        # Expected response from closed port is RST. Used to map open ports silently.
        elif flags == 0 or flags == "":
            meta["alerts"].append("NULL Scan Detected: No TCP flags set. Stealth mapping attempt.")

        # SYN Scan / SYN Flood Detection
        elif flags == "S":
            # Track SYN packets for flood detection
            self.syn_tracker[src_ip] = self.syn_tracker.get(src_ip, 0) + 1
            if self.syn_tracker[src_ip] > 100:
                meta["alerts"].append(f"SYN Flood Anomaly: {src_ip} sent >100 unacknowledged SYNs.")
            
            # Port Scan Tracking (Horizontal/Vertical)
            if src_ip not in self.port_scan_tracker:
                self.port_scan_tracker[src_ip] = set()
            self.port_scan_tracker[src_ip].add(meta["dst_port"])
            if len(self.port_scan_tracker[src_ip]) > 20:
                meta["alerts"].append(f"Port Scan Detected: {src_ip} scanning multiple ports.")

    def _analyze_udp(self, packet, meta):
        """Analyze UDP traffic, specifically looking for DNS tunneling."""
        if meta["dst_port"] == 53 or meta["src_port"] == 53:
            if packet.haslayer(Raw) and len(packet[Raw].load) > 200:
                # DNS packets are typically small. Massive TXT records indicate tunneling/C2.
                meta["alerts"].append("DNS Tunneling Indicator: Unusually large DNS payload.")

    def _check_arp_spoofing(self, packet, meta):
        """Maintains stateful IP-to-MAC mappings to detect MITM ARP poisoning."""
        if packet[ARP].op == 2: # ARP Reply (is-at)
            ip, mac = packet[ARP].psrc, packet[ARP].hwsrc
            if ip in self.arp_table and self.arp_table[ip] != mac:
                meta["alerts"].append(f"ARP Spoofing Detected: IP {ip} MAC changed from {self.arp_table[ip]} to {mac}!")
            else:
                self.arp_table[ip] = mac

    def _analyze_payload(self, raw_bytes, meta):
        """Regex-based DPI (Deep Packet Inspection) for cleartext credentials and malformed data."""
        payload_str = raw_bytes.decode('utf-8', errors='ignore')
        
        # FTP / Telnet cleartext credentials
        if re.search(r'(?i)^(USER|PASS) ', payload_str):
            meta["alerts"].append("Cleartext Credential: FTP/Telnet login sequence detected.")
        
        # HTTP Basic Auth (Base64 encoded but essentially cleartext)
        if re.search(r'(?i)Authorization:\sBasic\s', payload_str):
            meta["alerts"].append("Cleartext Credential: HTTP Basic Authentication detected.")
            
        # SQL Injection / XSS generic patterns
        if re.search(r'(?i)(UNION SELECT|DROP TABLE|<script>)', payload_str):
            meta["alerts"].append("Malicious Payload: SQLi/XSS patterns detected in raw bytes.")