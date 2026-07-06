import sys
import datetime
import warnings
import logging
import os

# --- SUPPRESS HARMFUL/ANNOYING WARNINGS ---
warnings.filterwarnings("ignore", category=DeprecationWarning) 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)     
# ------------------------------------------

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, 
                             QTextEdit, QLabel, QLineEdit, QTabWidget, QSplitter, QCheckBox)
from PyQt5.QtCore import pyqtSignal, QObject, Qt

class GUISignals(QObject):
    packet_received = pyqtSignal(dict)

class SentinelKaliGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel - Advanced IDS (Kali Linux Edition)")
        self.setGeometry(100, 100, 1400, 800)
        self._apply_dark_theme()

        self.signals = GUISignals()
        self.signals.packet_received.connect(self.update_gui)

        self.sniffer_thread = None
        self.packet_data_cache = [] 

        self.init_ui()

    def _apply_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #1e1e2e; }
            QWidget { color: #cdd6f4; font-family: 'Consolas', monospace; }
            QTableWidget { background-color: #181825; gridline-color: #313244; border: none; }
            QHeaderView::section { background-color: #313244; color: #cdd6f4; padding: 4px; border: 1px solid #1e1e2e;}
            QPushButton { background-color: #89b4fa; color: #11111b; font-weight: bold; padding: 6px; border-radius: 4px; }
            QPushButton:hover { background-color: #b4befe; }
            QTextEdit, QLineEdit { background-color: #11111b; border: 1px solid #45475a; padding: 4px; }
            QLabel, QCheckBox { font-weight: bold; }
        """)

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        controls_layout = QHBoxLayout()
        self.btn_start_ids = QPushButton("Start Live Capture (Kali Raw Sockets)")
        self.btn_stop = QPushButton("Stop Capture")
        self.btn_stop.setEnabled(False)
        
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Manual Filter (e.g., protocol==TCP)")
        self.filter_input.textChanged.connect(self.apply_filter)

        self.chk_autofilter = QCheckBox("Auto-Filter Suspicious Alerts")
        self.chk_autofilter.stateChanged.connect(self.apply_filter)

        controls_layout.addWidget(self.btn_start_ids)
        controls_layout.addWidget(self.btn_stop)
        controls_layout.addWidget(QLabel("Filter:"))
        controls_layout.addWidget(self.filter_input)
        controls_layout.addWidget(self.chk_autofilter)

        self.btn_start_ids.clicked.connect(self.start_ids)
        self.btn_stop.clicked.connect(self.stop_capture)
        main_layout.addLayout(controls_layout)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.capture_tab = QSplitter(Qt.Vertical)
        
        self.packet_table = QTableWidget(0, 7) 
        self.packet_table.setHorizontalHeaderLabels(["Time", "Source IP", "Dest IP", "Protocol", "Length", "Src Port", "Dst Port"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.packet_table.itemSelectionChanged.connect(self.display_packet_details)
        
        self.detail_inspector = QTextEdit()
        self.detail_inspector.setReadOnly(True)

        self.capture_tab.addWidget(self.packet_table)
        self.capture_tab.addWidget(self.detail_inspector)
        self.tabs.addTab(self.capture_tab, "Live Traffic")

        self.alerts_table = QTableWidget(0, 3)
        self.alerts_table.setHorizontalHeaderLabels(["Time", "Attacker IP", "Threat Reason"])
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.alerts_table.setStyleSheet("color: #f38ba8;")
        self.tabs.addTab(self.alerts_table, "IDS Alerts")

        self.status_label = QLabel("Status: Idle | Captured: 0 | Running as Root")
        main_layout.addWidget(self.status_label)

    def start_ids(self):
        from core.sniffer import PacketSniffer
        self.btn_start_ids.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.sniffer_thread = PacketSniffer(self.signals.packet_received.emit)
        self.sniffer_thread.start()
        self.status_label.setText("Status: Kali IDS Mode (Passive Listening)...")

    def stop_capture(self):
        if self.sniffer_thread: self.sniffer_thread.stop()
        self.btn_start_ids.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.status_label.setText("Status: Stopped.")

    def update_gui(self, meta):
        self.packet_data_cache.append(meta)
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        time_str = datetime.datetime.fromtimestamp(meta["timestamp"]).strftime('%H:%M:%S.%f')[:-3]
        
        self.packet_table.setItem(row, 0, QTableWidgetItem(time_str))
        self.packet_table.setItem(row, 1, QTableWidgetItem(str(meta["src_ip"])))
        self.packet_table.setItem(row, 2, QTableWidgetItem(str(meta["dst_ip"])))
        self.packet_table.setItem(row, 3, QTableWidgetItem(meta["protocol"]))
        self.packet_table.setItem(row, 4, QTableWidgetItem(str(meta["length"])))
        self.packet_table.setItem(row, 5, QTableWidgetItem(str(meta["src_port"])))
        self.packet_table.setItem(row, 6, QTableWidgetItem(str(meta["dst_port"])))
        self.packet_table.scrollToBottom()

        for alert in meta["alerts"]:
            arow = self.alerts_table.rowCount()
            self.alerts_table.insertRow(arow)
            self.alerts_table.setItem(arow, 0, QTableWidgetItem(time_str))
            self.alerts_table.setItem(arow, 1, QTableWidgetItem(str(meta["src_ip"])))
            self.alerts_table.setItem(arow, 2, QTableWidgetItem(alert))

        filter_text = self.filter_input.text().strip()
        show_suspicious = self.chk_autofilter.isChecked()
        match = True

        if filter_text:
            try:
                k, v = filter_text.split("==")
                if str(meta.get(k.strip().lower(), "")).lower() != v.strip().lower():
                    match = False
            except ValueError:
                pass

        if show_suspicious and match:
            if len(meta.get("alerts", [])) == 0:
                match = False

        self.packet_table.setRowHidden(row, not match)
        self.status_label.setText(f"Status: Running | Captured: {len(self.packet_data_cache)}")

    def display_packet_details(self):
        selected_rows = self.packet_table.selectedItems()
        if not selected_rows: return
        meta = self.packet_data_cache[selected_rows[0].row()]

        details = "=== PACKET METADATA ===\n" + "\n".join([f"{k.upper()}: {v}" for k, v in meta.items() if k not in ["payload_hex", "payload_ascii", "alerts"]])
        details += "\n\n=== THREAT ALERTS ===\n" + ("\n".join(meta["alerts"]) if meta["alerts"] else "None")
        details += f"\n\n=== HEX DUMP ===\n{meta['payload_hex']}\n\n=== ASCII PAYLOAD ===\n{meta['payload_ascii']}"
        self.detail_inspector.setPlainText(details)

    def apply_filter(self):
        filter_text = self.filter_input.text().strip()
        show_suspicious = self.chk_autofilter.isChecked()

        for row in range(self.packet_table.rowCount()):
            match = True
            meta = self.packet_data_cache[row]

            if filter_text:
                try:
                    k, v = filter_text.split("==")
                    if str(meta.get(k.strip().lower(), "")).lower() != v.strip().lower(): match = False
                except ValueError: pass 

            if show_suspicious and match and len(meta.get("alerts", [])) == 0:
                match = False
            
            self.packet_table.setRowHidden(row, not match)

if __name__ == "__main__":
    # OS-Specific Pre-Check for Kali Linux
    if os.geteuid() != 0:
        print("\n[!] FATAL ERROR: Sentinel requires root privileges on Kali Linux to sniff packets.")
        print("[!] Please run the script using 'sudo python3 main_kali.py'\n")
        sys.exit(1)

    app = QApplication(sys.argv)
    window = SentinelKaliGUI()
    window.show()
    sys.exit(app.exec_())