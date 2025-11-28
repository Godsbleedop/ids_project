import threading
import time
from collections import defaultdict

from scapy.all import ICMP, IP, TCP, UDP, sniff


class PacketCapture:
    def __init__(self):
        self.packets = []
        # Track connections explicitly (not defaultdict to avoid auto-creation)
        self.connections = {}
        # Track per-source and per-destination packet counts
        self.src_packet_counts = defaultdict(int)
        self.dst_packet_counts = defaultdict(int)
        self.capture_thread = None
        self.is_capturing = False
        self.packet_count = 0
        self.time_window = 2  # 2 second window for connection tracking

    def extract_features(self, packet):
        """Extract features compatible with UNSW-NB15 dataset"""
        
        # Initialize with UNSW-NB15 columns (default 0)
        features = {
            "dur": 0.0,
            "proto": "tcp",
            "service": "-",
            "state": "CON",
            "spkts": 0,
            "dpkts": 0,
            "sbytes": 0,
            "dbytes": 0,
            "rate": 0.0,
            "sttl": 0,
            "dttl": 0,
            "sload": 0.0,
            "dload": 0.0,
            "sloss": 0,
            "dloss": 0,
            "sinpkt": 0.0,
            "dinpkt": 0.0,
            "sjit": 0.0,
            "djit": 0.0,
            "swin": 0,
            "stcpb": 0,
            "dtcpb": 0,
            "dwin": 0,
            "tcprtt": 0.0,
            "synack": 0.0,
            "ackdat": 0.0,
            "smean": 0,
            "dmean": 0,
            "trans_depth": 0,
            "response_body_len": 0,
            "ct_srv_src": 0,
            "ct_state_ttl": 0,
            "ct_dst_ltm": 0,
            "ct_src_dport_ltm": 0,
            "ct_dst_sport_ltm": 0,
            "ct_dst_src_ltm": 0,
            "is_ftp_login": 0,
            "ct_ftp_cmd": 0,
            "ct_flw_http_mthd": 0,
            "ct_src_ltm": 0,
            "ct_srv_dst": 0,
            "is_sm_ips_ports": 0
        }

        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        current_time = time.time()
        
        # Basic Features
        features["sbytes"] = len(packet)
        features["sttl"] = ip_layer.ttl
        features["spkts"] = 1
        
        # Protocol
        if packet.haslayer(TCP):
            features["proto"] = "tcp"
            features["dwin"] = packet[TCP].window
            features["swin"] = packet[TCP].window # Approximation
            
            # Service Mapping
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            if dport == 80 or sport == 80: features["service"] = "http"
            elif dport == 21 or sport == 21: features["service"] = "ftp"
            elif dport == 22 or sport == 22: features["service"] = "ssh"
            elif dport == 53 or sport == 53: features["service"] = "dns"
            elif dport == 25 or sport == 25: features["service"] = "smtp"
            
            # State Mapping (Simplified)
            flags = packet[TCP].flags
            if flags & 0x02: features["state"] = "CON" # SYN
            elif flags & 0x01: features["state"] = "FIN"
            elif flags & 0x04: features["state"] = "RST"
            else: features["state"] = "CON"

        elif packet.haslayer(UDP):
            features["proto"] = "udp"
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                features["service"] = "dns"
            features["state"] = "INT" # No connection state in UDP
            
        elif packet.haslayer(ICMP):
            features["proto"] = "icmp"
            features["state"] = "ECO"

        # Connection Tracking - COMPLETELY REWRITTEN
        conn_key = f"{src_ip}_{dst_ip}"
        
        # Initialize connection if it doesn't exist
        if conn_key not in self.connections:
            self.connections[conn_key] = {
                "count": 0,
                "start_time": current_time,
                "last_time": current_time
            }
        
        # Update connection info
        conn_info = self.connections[conn_key]
        conn_info["count"] += 1
        conn_info["last_time"] = current_time
        
        # Increment source and destination counters
        self.src_packet_counts[src_ip] += 1
        self.dst_packet_counts[dst_ip] += 1
        
        # Duration
        features["dur"] = current_time - conn_info["start_time"]
        
        # Count features - NOW USING SIMPLE COUNTERS
        src_count = self.src_packet_counts[src_ip]
        dst_count = self.dst_packet_counts[dst_ip]
        
        features["ct_src_ltm"] = min(100, src_count)
        features["ct_dst_ltm"] = min(100, dst_count)
        features["ct_srv_src"] = min(100, src_count)
        features["ct_srv_dst"] = min(100, dst_count)
        
        if src_ip == dst_ip:
            features["is_sm_ips_ports"] = 1
        
        # DEBUG: Print key features for flood detection
        if dst_count > 5 or src_count > 5:
            print(f"[DEBUG] Packet: {src_ip} -> {dst_ip} | Proto: {features['proto']} | "
                  f"ct_src_ltm: {src_count}, ct_dst_ltm: {dst_count}")
            
        return features

    def packet_callback(self, packet):
        try:
            features = self.extract_features(packet)
            if features:
                self.packet_count += 1
                packet_info = {
                    "timestamp": float(time.time()),
                    "features": features,
                    "raw_info": {
                        "src": str(
                            packet[IP].src if packet.haslayer(IP) else "unknown"
                        ),
                        "dst": str(
                            packet[IP].dst if packet.haslayer(IP) else "unknown"
                        ),
                        "proto": str(features["proto"]),
                        "size": int(features["sbytes"]),
                    },
                }
                self.packets.append(packet_info)

                # OPTIMIZED: Keep only last 200 packets (reduced from 1000)
                if len(self.packets) > 200:
                    self.packets = self.packets[-100:]

                # Print packet count every 500 packets (reduced frequency)
                if self.packet_count % 500 == 0:
                    print(f"[*] Captured {self.packet_count} packets")
        except Exception:
            pass  # Silently ignore packet processing errors

    def start_capture(self, interface=None):
        if self.is_capturing:
            return

        self.is_capturing = True

        if not interface or interface == "":
            interface = None

        def capture():
            try:
                print(
                    f"[*] Starting packet capture on: {interface if interface else 'all interfaces'}"
                )
                print(f"[*] Promiscuous mode: ENABLED")
                sniff(
                    prn=self.packet_callback,
                    store=False,
                    iface=interface,
                    promisc=True,
                    stop_filter=lambda x: not self.is_capturing,
                )
            except Exception as e:
                print(f"[!] Capture error: {e}")
                self.is_capturing = False

        self.capture_thread = threading.Thread(target=capture, daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        print("[*] Stopping packet capture...")
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        print("[*] Capture stopped")

    def get_recent_packets(self, count=50):
        return self.packets[-count:]

    def get_stats(self):
        return {
            "total_packets": int(self.packet_count),
            "active_connections": int(len(self.connections)),
            "packets_in_memory": int(len(self.packets)),
        }

    def clear_data(self):
        self.packets = []
        self.connections.clear()
        self.src_packet_counts.clear()
        self.dst_packet_counts.clear()
        self.packet_count = 0
        print("[*] Packet data cleared")

    def inject_packet(self, packet_info):
        """Inject a packet from an external source (remote agent)"""
        try:
            # Add to local packet list
            self.packets.append(packet_info)
            self.packet_count += 1
            
            # Keep memory manageable
            if len(self.packets) > 1000:
                self.packets = self.packets[-500:]
                
            return True
        except Exception as e:
            print(f"[!] Error injecting packet: {e}")
            return False
