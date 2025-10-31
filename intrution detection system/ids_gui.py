#!/usr/bin/env python3
"""
Intrusion Detection System (IDS) - GUI Version with Tkinter
Modern dashboard with real-time alerts and statistics
"""

from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext
import sqlite3

# ==================== CONFIGURATION ====================

SYN_FLOOD_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 20
TIME_WINDOW = 10
SUSPICIOUS_IPS = ['192.168.1.100', '10.0.0.50']
DB_FILE = 'ids_alerts.db'

# ==================== DATABASE SETUP ====================

def init_database():
    """Initialize SQLite database for storing alerts"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            details TEXT,
            severity TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_alert_to_db(alert_type, details, severity):
    """Save alert to database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(
            'INSERT INTO alerts (timestamp, alert_type, details, severity) VALUES (?, ?, ?, ?)',
            (timestamp, alert_type, details, severity)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database error: {e}")

# ==================== IDS CORE ENGINE ====================

class IDSEngine:
    """Core IDS detection engine"""
    
    def __init__(self):
        self.syn_tracker = defaultdict(list)
        self.port_scan_tracker = defaultdict(set)
        self.data_lock = threading.Lock()
        self.stats = {
            'total_packets': 0,
            'syn_floods': 0,
            'port_scans': 0,
            'malformed': 0,
            'suspicious_ips': 0
        }
        self.is_running = False
        self.alert_callback = None
        self.cleanup_thread = None
        
    def set_alert_callback(self, callback):
        """Set callback function for alerts"""
        self.alert_callback = callback
    
    def cleanup_old_data(self):
        """Clean old tracking data periodically"""
        while self.is_running:
            time.sleep(TIME_WINDOW)
            current_time = time.time()
            
            with self.data_lock:
                for ip in list(self.syn_tracker.keys()):
                    self.syn_tracker[ip] = [t for t in self.syn_tracker[ip] 
                                           if current_time - t < TIME_WINDOW]
                    if not self.syn_tracker[ip]:
                        del self.syn_tracker[ip]
                
                self.port_scan_tracker.clear()
    
    def detect_syn_flood(self, packet):
        """Detect SYN flood attacks"""
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':
            src_ip = packet[IP].src
            current_time = time.time()
            
            with self.data_lock:
                self.syn_tracker[src_ip].append(current_time)
                recent_syns = [t for t in self.syn_tracker[src_ip] 
                              if current_time - t < TIME_WINDOW]
                
                if len(recent_syns) > SYN_FLOOD_THRESHOLD:
                    return True, src_ip, len(recent_syns)
        
        return False, None, 0
    
    def detect_port_scan(self, packet):
        """Detect port scanning"""
        if packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            
            with self.data_lock:
                self.port_scan_tracker[src_ip].add(dst_port)
                
                if len(self.port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
                    return True, src_ip, len(self.port_scan_tracker[src_ip])
        
        return False, None, 0
    
    def detect_malformed_packet(self, packet):
        """Detect malformed packets"""
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            
            if flags == 0:
                return True, packet[IP].src, "NULL scan"
            if flags & 0x29 == 0x29:
                return True, packet[IP].src, "XMAS scan"
            if flags & 0x03 == 0x03:
                return True, packet[IP].src, "SYN+FIN flags"
            if flags & 0x06 == 0x06:
                return True, packet[IP].src, "SYN+RST flags"
        
        return False, None, None
    
    def detect_suspicious_ip(self, packet):
        """Check for blacklisted IPs"""
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            if src_ip in SUSPICIOUS_IPS:
                return True, src_ip
        return False, None
    
    def analyze_packet(self, packet):
        """Analyze each packet for threats"""
        if not packet.haslayer(IP):
            return
        
        with self.data_lock:
            self.stats['total_packets'] += 1
        
        # Run all detections
        is_syn_flood, src_ip, count = self.detect_syn_flood(packet)
        if is_syn_flood:
            self.trigger_alert('SYN_FLOOD', f"SYN flood from {src_ip} ({count} SYNs)", 'HIGH')
        
        is_port_scan, src_ip, port_count = self.detect_port_scan(packet)
        if is_port_scan:
            self.trigger_alert('PORT_SCAN', f"Port scan from {src_ip} ({port_count} ports)", 'MEDIUM')
        
        is_malformed, src_ip, mal_type = self.detect_malformed_packet(packet)
        if is_malformed:
            self.trigger_alert('MALFORMED', f"Malformed packet from {src_ip} - {mal_type}", 'HIGH')
        
        is_suspicious, src_ip = self.detect_suspicious_ip(packet)
        if is_suspicious:
            self.trigger_alert('SUSPICIOUS_IP', f"Blacklisted IP: {src_ip}", 'CRITICAL')
    
    def trigger_alert(self, alert_type, details, severity):
        """Trigger alert callback"""
        with self.data_lock:
            key = alert_type.lower() + 's'
            if key in self.stats:
                self.stats[key] += 1
        
        if self.alert_callback:
            self.alert_callback(alert_type, details, severity)
        
        save_alert_to_db(alert_type, details, severity)
    
    def start_monitoring(self, interface=None):
        """Start packet capture"""
        self.is_running = True
        self.cleanup_thread = threading.Thread(target=self.cleanup_old_data, daemon=True)
        self.cleanup_thread.start()
        
        try:
            sniff(iface=interface, prn=self.analyze_packet, store=False, stop_filter=lambda x: not self.is_running)
        except Exception as e:
            if self.alert_callback:
                self.alert_callback('ERROR', f"Monitoring error: {e}", 'CRITICAL')
    
    def stop_monitoring(self):
        """Stop packet capture"""
        self.is_running = False

# ==================== GUI APPLICATION ====================

class IDSGui:
    """Modern GUI for IDS"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System - Dashboard")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1a1a2e')
        
        # Initialize interface selection
        self.selected_interface = tk.StringVar()
        self.get_network_interfaces()
        
        self.engine = IDSEngine()
        self.engine.set_alert_callback(self.handle_alert)
        self.monitoring_thread = None
        
        self.setup_gui()
        self.update_stats()
    
    def get_network_interfaces(self):
        """Get available network interfaces"""
        try:
            from scapy.arch import get_windows_if_list
            interfaces = get_windows_if_list()
            self.interfaces = {i['name']: i['description'] for i in interfaces}
            if self.interfaces:
                self.selected_interface.set(next(iter(self.interfaces.keys())))
        except Exception as e:
            self.interfaces = {"Default": "Default Interface"}
            self.selected_interface.set("Default")
            print(f"Error getting interfaces: {e}")
        
    def setup_gui(self):
        """Setup GUI components"""
        
        # Title bar
        title_frame = tk.Frame(self.root, bg='#16213e', height=80)
        title_frame.pack(fill='x', padx=0, pady=0)
        
        title_label = tk.Label(
            title_frame,
            text="🛡️ INTRUSION DETECTION SYSTEM",
            font=('Arial', 24, 'bold'),
            bg='#16213e',
            fg='#00ff88'
        )
        title_label.pack(pady=20)
        
        # Main container
        main_container = tk.Frame(self.root, bg='#1a1a2e')
        main_container.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Left panel - Controls and Stats
        left_panel = tk.Frame(main_container, bg='#16213e', width=350)
        left_panel.pack(side='left', fill='y', padx=(0, 10))
        left_panel.pack_propagate(False)
        
        # Network Interface Selection
        interface_frame = tk.LabelFrame(
            left_panel,
            text="🌐 NETWORK INTERFACE",
            font=('Arial', 12, 'bold'),
            bg='#16213e',
            fg='#00ff88',
            relief='groove',
            bd=2
        )
        interface_frame.pack(pady=10, padx=20, fill='x')
        
        self.interface_menu = ttk.Combobox(
            interface_frame,
            textvariable=self.selected_interface,
            values=list(self.interfaces.keys()),
            state='readonly',
            font=('Arial', 10)
        )
        self.interface_menu.pack(pady=10, padx=10, fill='x')
        
        # Control buttons
        control_frame = tk.Frame(left_panel, bg='#16213e')
        control_frame.pack(pady=20, padx=20, fill='x')
        
        self.start_button = tk.Button(
            control_frame,
            text="▶ START MONITORING",
            command=self.start_monitoring,
            bg='#00ff88',
            fg='#1a1a2e',
            font=('Arial', 12, 'bold'),
            relief='flat',
            cursor='hand2',
            height=2
        )
        self.start_button.pack(fill='x', pady=5)
        
        self.stop_button = tk.Button(
            control_frame,
            text="⏸ STOP MONITORING",
            command=self.stop_monitoring,
            bg='#ff4444',
            fg='white',
            font=('Arial', 12, 'bold'),
            relief='flat',
            cursor='hand2',
            height=2,
            state='disabled'
        )
        self.stop_button.pack(fill='x', pady=5)
        
        # Status indicator
        status_frame = tk.Frame(left_panel, bg='#16213e')
        status_frame.pack(pady=10, padx=20, fill='x')
        
        tk.Label(
            status_frame,
            text="STATUS:",
            font=('Arial', 10, 'bold'),
            bg='#16213e',
            fg='#ffffff'
        ).pack()
        
        self.status_label = tk.Label(
            status_frame,
            text="● OFFLINE",
            font=('Arial', 14, 'bold'),
            bg='#16213e',
            fg='#ff4444'
        )
        self.status_label.pack(pady=5)
        
        # Statistics frame
        stats_frame = tk.LabelFrame(
            left_panel,
            text="📊 STATISTICS",
            font=('Arial', 12, 'bold'),
            bg='#16213e',
            fg='#00ff88',
            relief='groove',
            bd=2
        )
        stats_frame.pack(pady=20, padx=20, fill='both', expand=True)
        
        # Stats labels
        self.stats_labels = {}
        stats_info = [
            ('total_packets', '📦 Total Packets', '#00d9ff'),
            ('syn_floods', '🌊 SYN Floods', '#ff4444'),
            ('port_scans', '🔍 Port Scans', '#ffaa00'),
            ('malformed', '⚠️ Malformed Packets', '#ff00ff'),
            ('suspicious_ips', '🚨 Suspicious IPs', '#ff0000')
        ]
        
        for key, label, color in stats_info:
            frame = tk.Frame(stats_frame, bg='#16213e')
            frame.pack(pady=8, padx=10, fill='x')
            
            tk.Label(
                frame,
                text=label,
                font=('Arial', 10),
                bg='#16213e',
                fg='#ffffff',
                anchor='w'
            ).pack(side='left')
            
            self.stats_labels[key] = tk.Label(
                frame,
                text="0",
                font=('Arial', 12, 'bold'),
                bg='#16213e',
                fg=color,
                anchor='e'
            )
            self.stats_labels[key].pack(side='right')
        
        # Right panel - Alerts
        right_panel = tk.Frame(main_container, bg='#16213e')
        right_panel.pack(side='right', fill='both', expand=True)
        
        alerts_header = tk.Label(
            right_panel,
            text="🚨 REAL-TIME ALERTS",
            font=('Arial', 14, 'bold'),
            bg='#16213e',
            fg='#00ff88'
        )
        alerts_header.pack(pady=10)
        
        # Alerts display
        self.alerts_text = scrolledtext.ScrolledText(
            right_panel,
            font=('Courier New', 10),
            bg='#0f0f1e',
            fg='#00ff88',
            insertbackground='#00ff88',
            relief='flat',
            wrap='word'
        )
        self.alerts_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Configure text tags for colored alerts
        self.alerts_text.tag_config('CRITICAL', foreground='#ff0000', font=('Courier New', 10, 'bold'))
        self.alerts_text.tag_config('HIGH', foreground='#ff4444', font=('Courier New', 10, 'bold'))
        self.alerts_text.tag_config('MEDIUM', foreground='#ffaa00', font=('Courier New', 10, 'bold'))
        self.alerts_text.tag_config('INFO', foreground='#00d9ff', font=('Courier New', 10))
        self.alerts_text.tag_config('timestamp', foreground='#888888')
        
        # Initial message
        self.add_alert_message("System initialized. Click START to begin monitoring.", 'INFO')
    
    def add_alert_message(self, message, severity='INFO'):
        """Add message to alerts display"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.alerts_text.insert('end', f"[{timestamp}] ", 'timestamp')
        self.alerts_text.insert('end', f"[{severity}] {message}\n", severity)
        self.alerts_text.see('end')
    
    def handle_alert(self, alert_type, details, severity):
        """Handle alerts from IDS engine"""
        self.root.after(0, self.add_alert_message, f"{alert_type}: {details}", severity)
    
    def update_stats(self):
        """Update statistics display"""
        if hasattr(self, 'stats_labels'):
            stats = self.engine.stats
            for key, label in self.stats_labels.items():
                label.config(text=str(stats.get(key, 0)))
        
        self.root.after(1000, self.update_stats)
    
    def start_monitoring(self):
        """Start IDS monitoring"""
        try:
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            self.interface_menu.config(state='disabled')
            self.status_label.config(text="● ONLINE", fg='#00ff88')
            
            selected_iface = self.selected_interface.get()
            self.add_alert_message(f"Starting monitoring on interface: {selected_iface}", 'INFO')
            
            self.monitoring_thread = threading.Thread(
                target=self.engine.start_monitoring,
                args=(selected_iface,),
                daemon=True
            )
            self.monitoring_thread.start()
        except Exception as e:
            self.add_alert_message(f"Error starting monitoring: {str(e)}", 'CRITICAL')
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop IDS monitoring"""
        self.engine.stop_monitoring()
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.interface_menu.config(state='readonly')
        self.status_label.config(text="● OFFLINE", fg='#ff4444')
        
        self.add_alert_message("Monitoring stopped.", 'INFO')

# ==================== MAIN ====================

def main():
    """Main entry point"""
    init_database()
    
    root = tk.Tk()
    app = IDSGui(root)
    root.mainloop()

if __name__ == "__main__":
    main()