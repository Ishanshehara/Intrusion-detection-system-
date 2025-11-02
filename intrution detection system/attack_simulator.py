#!/usr/bin/env python3
"""
Attack Simulator - For Testing IDS
WARNING: Use only on your own network for testing purposes!
Unauthorized network scanning/testing may be illegal.
"""

from scapy.all import IP, TCP, send, sr1, conf
import time
import sys
import random

# Suppress Scapy warnings
conf.verb = 0

class AttackSimulator:
    """Simulates various network attacks for IDS testing"""
    
    def __init__(self, target_ip, target_port=80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.test_results = []
        
    def print_banner(self):
        """Display banner"""
        print("\n" + "="*70)
        print("       🎯 IDS ATTACK SIMULATOR - FOR TESTING ONLY 🎯")
        print("="*70)
        print(f"Target IP: {self.target_ip}")
        print(f"Target Port: {self.target_port}")
        print("⚠️  WARNING: Only use on networks you own or have permission to test!")
        print("="*70 + "\n")
    
    def syn_flood_test(self, count=150, delay=0.01):
        """
        Simulate SYN flood attack
        
        Args:
            count: Number of SYN packets to send
            delay: Delay between packets (seconds)
        """
        print(f"\n[TEST 1] Simulating SYN Flood Attack")
        print(f"├─ Sending {count} SYN packets to {self.target_ip}:{self.target_port}")
        print("├─ This should trigger SYN_FLOOD alert in your IDS")
        print("└─ Progress: ", end="", flush=True)
        
        success_count = 0
        start_time = time.time()
        
        try:
            for i in range(count):
                # Create SYN packet with random source port
                src_port = random.randint(1024, 65535)
                packet = IP(dst=self.target_ip)/TCP(sport=src_port, dport=self.target_port, flags='S')
                
                # Send packet
                send(packet, verbose=False)
                success_count += 1
                
                # Progress indicator
                if i % 30 == 0:
                    print("█", end="", flush=True)
                
                time.sleep(delay)
            
            elapsed = time.time() - start_time
            print(f"\n✅ SYN Flood test complete: {success_count}/{count} packets sent in {elapsed:.2f}s")
            self.test_results.append(("SYN Flood", success_count, count))
            
        except Exception as e:
            print(f"\n❌ Error during SYN flood test: {e}")
            self.test_results.append(("SYN Flood", success_count, count))
    
    def port_scan_test(self, start_port=1, end_port=30, delay=0.05):
        """
        Simulate port scanning attack
        
        Args:
            start_port: First port to scan
            end_port: Last port to scan
            delay: Delay between port scans
        """
        print(f"\n[TEST 2] Simulating Port Scan Attack")
        print(f"├─ Scanning ports {start_port}-{end_port} on {self.target_ip}")
        print("├─ This should trigger PORT_SCAN alert in your IDS")
        print("└─ Progress: ", end="", flush=True)
        
        scanned_ports = 0
        start_time = time.time()
        
        try:
            for port in range(start_port, end_port + 1):
                # Create SYN packet for each port
                packet = IP(dst=self.target_ip)/TCP(dport=port, flags='S')
                send(packet, verbose=False)
                scanned_ports += 1
                
                # Progress indicator
                if port % 5 == 0:
                    print("█", end="", flush=True)
                
                time.sleep(delay)
            
            elapsed = time.time() - start_time
            print(f"\n✅ Port scan test complete: {scanned_ports} ports scanned in {elapsed:.2f}s")
            self.test_results.append(("Port Scan", scanned_ports, end_port - start_port + 1))
            
        except Exception as e:
            print(f"\n❌ Error during port scan test: {e}")
            self.test_results.append(("Port Scan", scanned_ports, end_port - start_port + 1))
    
    def xmas_scan_test(self, count=10):
        """
        Simulate XMAS scan (FIN, PSH, URG flags set)
        
        Args:
            count: Number of XMAS packets to send
        """
        print(f"\n[TEST 3] Simulating XMAS Scan Attack")
        print(f"├─ Sending {count} XMAS packets (FIN+PSH+URG flags)")
        print("├─ This should trigger MALFORMED alert in your IDS")
        print("└─ Progress: ", end="", flush=True)
        
        success_count = 0
        
        try:
            for i in range(count):
                # XMAS scan: FIN + PSH + URG flags
                packet = IP(dst=self.target_ip)/TCP(dport=self.target_port, flags='FPU')
                send(packet, verbose=False)
                success_count += 1
                print("█", end="", flush=True)
                time.sleep(0.2)
            
            print(f"\n✅ XMAS scan test complete: {success_count}/{count} packets sent")
            self.test_results.append(("XMAS Scan", success_count, count))
            
        except Exception as e:
            print(f"\n❌ Error during XMAS scan test: {e}")
            self.test_results.append(("XMAS Scan", success_count, count))
    
    def null_scan_test(self, count=10):
        """
        Simulate NULL scan (no flags set)
        
        Args:
            count: Number of NULL packets to send
        """
        print(f"\n[TEST 4] Simulating NULL Scan Attack")
        print(f"├─ Sending {count} NULL packets (no flags set)")
        print("├─ This should trigger MALFORMED alert in your IDS")
        print("└─ Progress: ", end="", flush=True)
        
        success_count = 0
        
        try:
            for i in range(count):
                # NULL scan: No flags set
                packet = IP(dst=self.target_ip)/TCP(dport=self.target_port, flags='')
                send(packet, verbose=False)
                success_count += 1
                print("█", end="", flush=True)
                time.sleep(0.2)
            
            print(f"\n✅ NULL scan test complete: {success_count}/{count} packets sent")
            self.test_results.append(("NULL Scan", success_count, count))
            
        except Exception as e:
            print(f"\n❌ Error during NULL scan test: {e}")
            self.test_results.append(("NULL Scan", success_count, count))
    
    def fin_scan_test(self, count=10):
        """
        Simulate FIN scan
        
        Args:
            count: Number of FIN packets to send
        """
        print(f"\n[TEST 5] Simulating FIN Scan Attack")
        print(f"├─ Sending {count} FIN packets")
        print("├─ This may trigger alerts depending on IDS configuration")
        print("└─ Progress: ", end="", flush=True)
        
        success_count = 0
        
        try:
            for i in range(count):
                # FIN scan
                packet = IP(dst=self.target_ip)/TCP(dport=self.target_port, flags='F')
                send(packet, verbose=False)
                success_count += 1
                print("█", end="", flush=True)
                time.sleep(0.2)
            
            print(f"\n✅ FIN scan test complete: {success_count}/{count} packets sent")
            self.test_results.append(("FIN Scan", success_count, count))
            
        except Exception as e:
            print(f"\n❌ Error during FIN scan test: {e}")
            self.test_results.append(("FIN Scan", success_count, count))
    
    def mixed_attack_test(self, duration=30):
        """
        Simulate mixed attack patterns
        
        Args:
            duration: How long to run the mixed attack (seconds)
        """
        print(f"\n[TEST 6] Simulating Mixed Attack Pattern")
        print(f"├─ Running random attacks for {duration} seconds")
        print("├─ This should trigger multiple alert types")
        print("└─ Running...", end="", flush=True)
        
        start_time = time.time()
        attack_count = 0
        
        try:
            while time.time() - start_time < duration:
                attack_type = random.choice(['syn', 'port', 'xmas', 'null'])
                
                if attack_type == 'syn':
                    # Quick SYN burst
                    for _ in range(10):
                        packet = IP(dst=self.target_ip)/TCP(dport=random.randint(1, 1024), flags='S')
                        send(packet, verbose=False)
                        attack_count += 1
                
                elif attack_type == 'port':
                    # Random port scan
                    port = random.randint(1, 65535)
                    packet = IP(dst=self.target_ip)/TCP(dport=port, flags='S')
                    send(packet, verbose=False)
                    attack_count += 1
                
                elif attack_type == 'xmas':
                    # XMAS packet
                    packet = IP(dst=self.target_ip)/TCP(dport=self.target_port, flags='FPU')
                    send(packet, verbose=False)
                    attack_count += 1
                
                elif attack_type == 'null':
                    # NULL packet
                    packet = IP(dst=self.target_ip)/TCP(dport=self.target_port, flags='')
                    send(packet, verbose=False)
                    attack_count += 1
                
                if attack_count % 50 == 0:
                    print(".", end="", flush=True)
                
                time.sleep(0.05)
            
            elapsed = time.time() - start_time
            print(f"\n✅ Mixed attack test complete: {attack_count} packets sent in {elapsed:.2f}s")
            self.test_results.append(("Mixed Attack", attack_count, attack_count))
            
        except Exception as e:
            print(f"\n❌ Error during mixed attack test: {e}")
            self.test_results.append(("Mixed Attack", attack_count, attack_count))
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*70)
        print("                        TEST SUMMARY")
        print("="*70)
        print(f"{'Test Name':<20} {'Sent':<10} {'Total':<10} {'Status':<15}")
        print("-"*70)
        
        for test_name, sent, total in self.test_results:
            status = "✅ PASSED" if sent == total else "⚠️  PARTIAL"
            print(f"{test_name:<20} {sent:<10} {total:<10} {status:<15}")
        
        print("="*70)
        print("\n📋 Next Steps:")
        print("   1. Check your IDS terminal/GUI for alerts")
        print("   2. Review the alerts.log or ids_alerts.db file")
        print("   3. Verify all attack types were detected correctly")
        print("\n🎯 Expected Alerts:")
        print("   • SYN_FLOOD - From Test 1 and 6")
        print("   • PORT_SCAN - From Test 2 and 6")
        print("   • MALFORMED - From Tests 3, 4, 5, and 6")
        print("\n")

def main():
    """Main entry point"""
    
    # Default target (localhost for safe testing)
    target_ip = "127.0.0.1"
    target_port = 80
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
    if len(sys.argv) > 2:
        target_port = int(sys.argv[2])
    
    # Create simulator
    simulator = AttackSimulator(target_ip, target_port)
    simulator.print_banner()
    
    # Confirm before proceeding
    print("⚠️  This will generate simulated network attacks.")
    response = input("Type 'YES' to continue: ")
    
    if response.upper() != 'YES':
        print("Aborted.")
        return
    
    print("\n🚀 Starting attack simulation in 3 seconds...")
    time.sleep(3)
    
    try:
        # Run all tests
        simulator.syn_flood_test(count=150, delay=0.01)
        time.sleep(2)
        
        simulator.port_scan_test(start_port=1, end_port=30, delay=0.05)
        time.sleep(2)
        
        simulator.xmas_scan_test(count=10)
        time.sleep(2)
        
        simulator.null_scan_test(count=10)
        time.sleep(2)
        
        simulator.fin_scan_test(count=10)
        time.sleep(2)
        
        simulator.mixed_attack_test(duration=20)
        
        # Print summary
        simulator.print_summary()
        
    except KeyboardInterrupt:
        print("\n\n⏸️  Tests interrupted by user")
        simulator.print_summary()
    except PermissionError:
        print("\n❌ ERROR: Permission denied!")
        print("You need root/administrator privileges to send raw packets.")
        print("Run with: sudo python3 attack_simulator.py")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()