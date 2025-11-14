from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time
import threading

class PacketCapture:
    def __init__(self):
        self.packets = []
        self.connections = defaultdict(lambda: {
            'count': 0,
            'srv_count': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            'start_time': time.time(),
            'last_time': time.time(),
            'flags': set()
        })
        self.capture_thread = None
        self.is_capturing = False
        self.packet_count = 0
        
    def extract_features(self, packet):
        features = {
            'duration': 0,
            'protocol_type': 'tcp',
            'service': 'other',
            'flag': 'SF',
            'src_bytes': 0,
            'dst_bytes': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 0,
            'srv_count': 0,
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 0.0,
            'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 0,
            'dst_host_srv_count': 0,
            'dst_host_same_srv_rate': 0.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }
        
        if not packet.haslayer(IP):
            return None
            
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        conn_key = f"{src_ip}_{dst_ip}"
        
        if packet.haslayer(TCP):
            features['protocol_type'] = 'tcp'
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            
            if dst_port == 80 or src_port == 80:
                features['service'] = 'http'
            elif dst_port == 443 or src_port == 443:
                features['service'] = 'https'
            elif dst_port == 21 or src_port == 21:
                features['service'] = 'ftp'
            elif dst_port == 22 or src_port == 22:
                features['service'] = 'ssh'
            elif dst_port == 25 or src_port == 25:
                features['service'] = 'smtp'
            elif dst_port == 53 or src_port == 53:
                features['service'] = 'domain'
            else:
                features['service'] = 'other'
            
            flags = tcp_layer.flags
            if flags & 0x02 and flags & 0x10:
                features['flag'] = 'SF'
            elif flags & 0x04:
                features['flag'] = 'REJ'
            elif flags & 0x02:
                features['flag'] = 'S0'
            else:
                features['flag'] = 'OTH'
                
        elif packet.haslayer(UDP):
            features['protocol_type'] = 'udp'
            udp_layer = packet[UDP]
            dst_port = udp_layer.dport
            
            if dst_port == 53:
                features['service'] = 'domain'
            else:
                features['service'] = 'other'
                
        elif packet.haslayer(ICMP):
            features['protocol_type'] = 'icmp'
            features['service'] = 'eco_i'
        
        packet_size = len(packet)
        features['src_bytes'] = packet_size
        features['dst_bytes'] = 0
        
        if src_ip == dst_ip:
            features['land'] = 1
        
        conn_info = self.connections[conn_key]
        conn_info['count'] += 1
        conn_info['src_bytes'] += packet_size
        conn_info['last_time'] = time.time()
        
        features['duration'] = int(conn_info['last_time'] - conn_info['start_time'])
        features['count'] = conn_info['count']
        features['srv_count'] = conn_info['srv_count']
        
        if features['count'] > 0:
            features['same_srv_rate'] = min(1.0, features['srv_count'] / features['count'])
        
        features['dst_host_count'] = min(255, len(self.connections))
        
        return features
    
    def packet_callback(self, packet):
        try:
            features = self.extract_features(packet)
            if features:
                self.packet_count += 1
                
                packet_info = {
                    'timestamp': float(time.time()),
                    'features': features,
                    'raw_info': {
                        'src': str(packet[IP].src if packet.haslayer(IP) else 'unknown'),
                        'dst': str(packet[IP].dst if packet.haslayer(IP) else 'unknown'),
                        'proto': str(features['protocol_type']),
                        'size': int(features['src_bytes'])
                    }
                }
                
                self.packets.append(packet_info)
                
                if len(self.packets) > 1000:
                    self.packets = self.packets[-500:]
                    
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def start_capture(self, interface=None):
        if self.is_capturing:
            return
        
        self.is_capturing = True
        
        if not interface or interface == "":
            interface = None
        
        def capture():
            try:
                print(f"Starting packet capture on interface: {interface if interface else 'all'}")
                sniff(prn=self.packet_callback, store=False, iface=interface, stop_filter=lambda x: not self.is_capturing)
            except Exception as e:
                print(f"Capture error: {e}")
                self.is_capturing = False
        
        self.capture_thread = threading.Thread(target=capture, daemon=True)
        self.capture_thread.start()
    
    def stop_capture(self):
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
    
    def get_recent_packets(self, count=50):
        return self.packets[-count:]
    
    def get_stats(self):
        return {
            'total_packets': int(self.packet_count),
            'active_connections': int(len(self.connections)),
            'packets_in_memory': int(len(self.packets))
        }
    
    def clear_data(self):
        self.packets = []
        self.connections.clear()
        self.packet_count = 0
