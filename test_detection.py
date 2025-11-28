#!/usr/bin/env python3
"""
Quick test to verify packet feature extraction is working
"""
import sys
sys.path.insert(0, '/home/aaron/ids_project')

from packet_capture import PacketCapture
from scapy.all import IP, ICMP, send

print("Testing packet feature extraction...")
print("=" * 60)

# Create packet capture instance
pc = PacketCapture()

# Simulate multiple ICMP packets from same source to same dest
test_src = "192.168.1.100"
test_dst = "192.168.100.10"

print(f"\nSimulating 10 ICMP packets: {test_src} -> {test_dst}")
print("-" * 60)

for i in range(10):
    # Create test packet
    pkt = IP(src=test_src, dst=test_dst)/ICMP()
    
    # Extract features
    features = pc.extract_features(pkt)
    
    if features:
        print(f"Packet {i+1}: ct_src_ltm={features['ct_src_ltm']}, "
              f"ct_dst_ltm={features['ct_dst_ltm']}, "
              f"proto={features['proto']}")

print("\n" + "=" * 60)
print("Expected: ct_dst_ltm should increase from 1 to 10")
print("If ct_dst_ltm stays at 1, the connection tracking is broken")
