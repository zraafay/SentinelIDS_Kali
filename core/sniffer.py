from scapy.all import sniff, wrpcap, rdpcap
import threading
from core.analyzer import PacketAnalyzer

class PacketSniffer(threading.Thread):
    def __init__(self, gui_callback):
        super().__init__()
        self.daemon = True
        self.gui_callback = gui_callback
        self.analyzer = PacketAnalyzer()
        self.is_running = False
        self.captured_packets = []

    def run(self):
        self.is_running = True
        # Sniff continuously. 'store=False' prevents memory leaks for massive captures.
        # prn routes each packet to our processing function.
        sniff(prn=self.process_packet, store=False, stop_filter=self.should_stop)

    def process_packet(self, packet):
        if not self.is_running: return
        
        # Store raw scapy packet for PCAP export
        self.captured_packets.append(packet)
        
        # Run forensic analysis
        meta = self.analyzer.analyze_packet(packet)
        
        # Send metadata to GUI safely
        self.gui_callback(meta)

    def should_stop(self, packet):
        return not self.is_running

    def stop(self):
        self.is_running = False

    def save_pcap(self, filename):
        wrpcap(filename, self.captured_packets)

    def load_pcap(self, filename):
        self.captured_packets = rdpcap(filename)
        for pkt in self.captured_packets:
            meta = self.analyzer.analyze_packet(pkt)
            self.gui_callback(meta)