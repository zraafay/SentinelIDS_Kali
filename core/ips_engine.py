import threading
from netfilterqueue import NetfilterQueue
from scapy.all import IP
from core.analyzer import PacketAnalyzer

class IPSEngine(threading.Thread):
    def __init__(self, gui_callback):
        super().__init__()
        self.daemon = True
        self.gui_callback = gui_callback
        self.analyzer = PacketAnalyzer()
        self.is_running = False
        self.nfqueue = NetfilterQueue()
        self.blocked_count = 0

    def run(self):
        self.is_running = True
        # Bind to queue-num 1 (Must match iptables setup script)
        self.nfqueue.bind(1, self.process_nf_packet)
        try:
            self.nfqueue.run()
        except Exception as e:
            print(f"[!] IPS Engine Error: {e}")

    def process_nf_packet(self, nf_packet):
        """
        Triggered by Linux Kernel via netfilter.
        We extract the raw payload, cast it to a Scapy IP packet, and run our IDS rules.
        """
        raw_data = nf_packet.get_payload()
        scapy_pkt = IP(raw_data)
        
        # Run stateful analysis
        meta = self.analyzer.analyze_packet(scapy_pkt)
        
        # Active Blocking Logic
        drop_packet = False
        
        # 1. Whitelist Bypass
        if meta["src_ip"] in self.analyzer.whitelist:
            drop_packet = False
        # 2. Block Blacklisted IPs or if Alerts were generated
        elif meta["src_ip"] in self.analyzer.blacklist or len(meta["alerts"]) > 0:
            drop_packet = True

        if drop_packet:
            meta["action"] = "DROPPED"
            self.blocked_count += 1
            nf_packet.drop()  # Instruct Kernel to drop
        else:
            meta["action"] = "ACCEPTED"
            nf_packet.accept() # Instruct Kernel to forward normally

        # Update GUI
        self.gui_callback(meta)

    def stop(self):
        self.is_running = False
        self.nfqueue.unbind()