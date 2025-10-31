#!/usr/bin/env python3
"""
Intrusion Detection System (IDS) - Terminal Version
Detects SYN floods, port scans, malformed packets, and suspicious IPs
"""

from scapy.all import sniff, IP, TCP, ICMP
from collections import defaultdict
from datetime import datetime
import threading
import time
import logging

# ==================== CONFIGURATION ====================

# Thresholds for detection
SYN_FLOOD_THRESHOLD = 100  # SYN packets per IP in time window
PORT_SCAN_THRESHOLD = 20   # Different ports accessed per IP in time window
TIME_WINDOW = 10           # Seconds to track patterns
SUSPICIOUS_IPS = ['192.168.1.100', '10.0.0.50']  # Example blacklist

# Logging configuration
LOG_FILE = 'alerts.log'
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ==================== DATA STRUCTURES ====================

# Track SYN packets per source IP
syn_tracker = defaultdict(list)

# Track ports accessed per source IP
port_scan_tracker = defaultdict(set)

# Store all alerts for statistics
alert_history = []

# Thread-safe lock for shared data
data_lock = threading.Lock()

# Statistics
stats = {
    'total_packets': 0,
    'syn_floods': 0,
    'port_scans': 0,
    'malformed': 0,
    'suspicious_ips': 0
}

# ==================== CLEANUP THREAD ====================

def cleanup_old_data():
    """
    Background thread that periodically cleans old tracking data
    to prevent memory overflow
    """
    while True:
        time.sleep(TIME_WINDOW)
        current_time = time.time()
        
        with data_lock:
            # Clean SYN tracker
            for ip in list(syn_tracker.keys()):
                syn_tracker[ip] = [t for t in syn_tracker[ip] 
                                   if current_time - t < TIME_WINDOW]
                if not syn_tracker[ip]:
                    del syn_tracker[ip]
            
            # Clean port scan tracker (reset every window)
            port_scan_tracker.clear()

# ==================== DETECTION FUNCTIONS ====================

def detect_syn_flood(packet):
    """
    Detect SYN flood attacks by counting SYN packets per IP
    Returns: True if SYN flood detected, False otherwise
    """
    if packet.haslayer(TCP) and packet[TCP].flags == 'S':  # SYN flag only
        src_ip = packet[IP].src
        current_time = time.time()
        
        with data_lock:
            syn_tracker[src_ip].append(current_time)
            
            # Count SYNs in the current time window
            recent_syns = [t for t in syn_tracker[src_ip] 
                          if current_time - t < TIME_WINDOW]
            
            if len(recent_syns) > SYN_FLOOD_THRESHOLD:
                return True, src_ip, len(recent_syns)
    
    return False, None, 0

def detect_port_scan(packet):
    """
    Detect port scanning by tracking different ports accessed per IP
    Returns: True if port scan detected, False otherwise
    """
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        
        with data_lock:
            port_scan_tracker[src_ip].add(dst_port)
            
            if len(port_scan_tracker[src_ip]) > PORT_SCAN_THRESHOLD:
                return True, src_ip, len(port_scan_tracker[src_ip])
    
    return False, None, 0

def detect_malformed_packet(packet):
    """
    Detect malformed packets with abnormal TCP flag combinations
    Returns: True if malformed packet detected, False otherwise
    """
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        
        # Check for suspicious flag combinations
        # NULL scan (no flags)
        if flags == 0:
            return True, packet[IP].src, "NULL scan (no flags)"
        
        # XMAS scan (FIN, PSH, URG)
        if flags & 0x29 == 0x29:  # FIN + PSH + URG
            return True, packet[IP].src, "XMAS scan (FIN+PSH+URG)"
        
        # SYN + FIN (invalid combination)
        if flags & 0x03 == 0x03:  # SYN + FIN
            return True, packet[IP].src, "Invalid SYN+FIN flags"
        
        # SYN + RST (invalid combination)
        if flags & 0x06 == 0x06:  # SYN + RST
            return True, packet[IP].src, "Invalid SYN+RST flags"
    
    return False, None, None

def detect_suspicious_ip(packet):
    """
    Check if packet is from a blacklisted/suspicious IP
    Returns: True if suspicious IP detected, False otherwise
    """
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        if src_ip in SUSPICIOUS_IPS:
            return True, src_ip
    
    return False, None

# ==================== ALERT HANDLING ====================

def generate_alert(alert_type, details):
    """
    Generate and log security alerts
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    alert_msg = f"[{alert_type}] {details}"
    
    # Print to console with color
    color_codes = {
        'SYN_FLOOD': '\033[91m',  # Red
        'PORT_SCAN': '\033[93m',  # Yellow
        'MALFORMED': '\033[95m',  # Magenta
        'SUSPICIOUS_IP': '\033[94m'  # Blue
    }
    reset_code = '\033[0m'
    
    colored_msg = f"{color_codes.get(alert_type, '')}{alert_msg}{reset_code}"
    print(f"[{timestamp}] {colored_msg}")
    
    # Log to file
    logging.warning(alert_msg)
    
    # Store in history
    with data_lock:
        alert_history.append({
            'timestamp': timestamp,
            'type': alert_type,
            'details': details
        })
        stats[alert_type.lower() + 's'] = stats.get(alert_type.lower() + 's', 0) + 1

# ==================== PACKET ANALYSIS ====================

def analyze_packet(packet):
    """
    Main packet analysis function - runs all detection checks
    """
    if not packet.haslayer(IP):
        return
    
    with data_lock:
        stats['total_packets'] += 1
    
    # Check for SYN flood
    is_syn_flood, src_ip, count = detect_syn_flood(packet)
    if is_syn_flood:
        generate_alert('SYN_FLOOD', f"Possible SYN flood from {src_ip} ({count} SYNs)")
    
    # Check for port scan
    is_port_scan, src_ip, port_count = detect_port_scan(packet)
    if is_port_scan:
        generate_alert('PORT_SCAN', f"Port scan detected from {src_ip} ({port_count} ports)")
    
    # Check for malformed packets
    is_malformed, src_ip, mal_type = detect_malformed_packet(packet)
    if is_malformed:
        generate_alert('MALFORMED', f"Malformed packet from {src_ip} - {mal_type}")
    
    # Check for suspicious IPs
    is_suspicious, src_ip = detect_suspicious_ip(packet)
    if is_suspicious:
        generate_alert('SUSPICIOUS_IP', f"Traffic from blacklisted IP: {src_ip}")

# ==================== STATISTICS DISPLAY ====================

def display_statistics():
    """
    Periodically display IDS statistics
    """
    while True:
        time.sleep(30)  # Display every 30 seconds
        print("\n" + "="*60)
        print("IDS STATISTICS")
        print("="*60)
        with data_lock:
            print(f"Total Packets Analyzed: {stats['total_packets']}")
            print(f"SYN Flood Alerts: {stats['syn_floods']}")
            print(f"Port Scan Alerts: {stats['port_scans']}")
            print(f"Malformed Packet Alerts: {stats['malformed']}")
            print(f"Suspicious IP Alerts: {stats['suspicious_ips']}")
        print("="*60 + "\n")

# ==================== MAIN FUNCTION ====================

def start_ids(interface=None):
    """
    Start the Intrusion Detection System
    
    Args:
        interface: Network interface to monitor (e.g., 'eth0', 'wlan0')
                   If None, uses default interface
    """
    print("\n" + "="*60)
    print("INTRUSION DETECTION SYSTEM - STARTED")
    print("="*60)
    print(f"Monitoring interface: {interface if interface else 'default'}")
    print(f"Alert log file: {LOG_FILE}")
    print(f"Time window: {TIME_WINDOW} seconds")
    print(f"SYN flood threshold: {SYN_FLOOD_THRESHOLD} packets")
    print(f"Port scan threshold: {PORT_SCAN_THRESHOLD} ports")
    print("="*60 + "\n")
    print("Press Ctrl+C to stop monitoring\n")
    
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_old_data, daemon=True)
    cleanup_thread.start()
    
    # Start statistics display thread
    stats_thread = threading.Thread(target=display_statistics, daemon=True)
    stats_thread.start()
    
    # Start packet capture
    try:
        sniff(iface=interface, prn=analyze_packet, store=False)
    except KeyboardInterrupt:
        print("\n\nIDS stopped by user")
        print(f"Total packets analyzed: {stats['total_packets']}")
        print(f"Check {LOG_FILE} for complete alert history")
    except PermissionError:
        print("\nERROR: Permission denied. Run with sudo/administrator privileges:")
        print("  sudo python3 ids_terminal.py")
    except Exception as e:
        print(f"\nERROR: {e}")

# ==================== ENTRY POINT ====================

if __name__ == "__main__":
    import sys
    
    # Optional: specify network interface as command-line argument
    interface = sys.argv[1] if len(sys.argv) > 1 else None
    
    start_ids(interface)