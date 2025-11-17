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
            'flags': set(),
            'syn_count': 0,
            'fin_count': 0,
            'rst_count': 0,
            'error_count': 0,
            'service': None
        })
        self.host_connections = defaultdict(lambda: {
            'connections': [],
            'services': set(),
            'src_ports': set()
        })
        self.capture_thread = None
        self.is_capturing = False
        self.packet_count = 0
        self.time_window = 2

    def extract_features(self, packet):
        """Extract network features from packet - ALREADY ENCODED"""
        
        features = {
            'duration': 0,
            'protocol_type': 6,
            'service': 11,
            'flag': 0,
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
        current_time = time.time()

        # Land attack
        if src_ip == dst_ip:
            features['land'] = 1

        service_code = 11
        src_port = 0
        dst_port = 0

        if packet.haslayer(TCP):
            features['protocol_type'] = 6
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport

            # Service mapping
            service_map = {
                20: 0, 21: 0,
                22: 1,
                23: 2,
                25: 3,
                53: 4,
                80: 5,
                110: 6,
                143: 7,
                443: 8,
                3306: 9, 5432: 9,
                3389: 10,
            }
            
            service_code = service_map.get(dst_port, service_map.get(src_port, 11))
            features['service'] = service_code

            if service_code in [0, 1, 2]:
                features['logged_in'] = 1

            # TCP flags
            flags = int(tcp_layer.flags)
            conn_key = f"{src_ip}_{dst_ip}_{dst_port}"
            
            if flags & 0x01:
                features['flag'] = 3
                self.connections[conn_key]['fin_count'] += 1
            elif flags & 0x04:
                features['flag'] = 4
                self.connections[conn_key]['rst_count'] += 1
                self.connections[conn_key]['error_count'] += 1
            elif flags & 0x02:
                if flags & 0x10:
                    features['flag'] = 1
                else:
                    features['flag'] = 0
                    self.connections[conn_key]['syn_count'] += 1
            elif flags & 0x10:
                features['flag'] = 2
            else:
                features['flag'] = 5

            if tcp_layer.urgptr:
                features['urgent'] = 1

        elif packet.haslayer(UDP):
            features['protocol_type'] = 17
            udp_layer = packet[UDP]
            dst_port = udp_layer.dport
            src_port = udp_layer.sport
            
            service_code = 4 if (dst_port == 53 or src_port == 53) else 11
            features['service'] = service_code

        elif packet.haslayer(ICMP):
            features['protocol_type'] = 1
            features['service'] = 12
            service_code = 12

        # Packet size
        packet_size = len(packet)
        features['src_bytes'] = packet_size

        # Connection tracking
        conn_key = f"{src_ip}_{dst_ip}_{dst_port}"
        conn_info = self.connections[conn_key]
        
        conn_info['count'] += 1
        conn_info['src_bytes'] += packet_size
        conn_info['last_time'] = current_time
        if conn_info['service'] is None:
            conn_info['service'] = service_code

        # Duration
        features['duration'] = int(current_time - conn_info['start_time'])

        # Same destination connections
        same_dest_conns = [k for k, v in self.connections.items() 
                          if k.startswith(f"{src_ip}_") and 
                          current_time - v['last_time'] < self.time_window]
        
        features['count'] = min(511, len(same_dest_conns))
        
        # Same service connections
        same_srv_conns = [k for k in same_dest_conns 
                         if self.connections[k]['service'] == service_code]
        features['srv_count'] = min(511, len(same_srv_conns))

        # Error rates - KEY FOR ATTACK DETECTION
        if features['count'] > 0:
            error_conns = sum(1 for k in same_dest_conns 
                            if self.connections[k]['error_count'] > 0)
            syn_only_conns = sum(1 for k in same_dest_conns 
                               if self.connections[k]['syn_count'] > self.connections[k]['fin_count'] + 2)
            
            total_errors = error_conns + syn_only_conns
            features['serror_rate'] = min(1.0, total_errors / features['count'])
            features['rerror_rate'] = min(1.0, error_conns / features['count'])
            
            if features['srv_count'] > 0:
                srv_errors = sum(1 for k in same_srv_conns 
                               if self.connections[k]['error_count'] > 0)
                srv_syn_only = sum(1 for k in same_srv_conns 
                                  if self.connections[k]['syn_count'] > self.connections[k]['fin_count'] + 2)
                
                features['srv_serror_rate'] = min(1.0, (srv_errors + srv_syn_only) / features['srv_count'])
                features['srv_rerror_rate'] = min(1.0, srv_errors / features['srv_count'])

        # Service rates
        if features['count'] > 0:
            features['same_srv_rate'] = features['srv_count'] / features['count']
            features['diff_srv_rate'] = 1.0 - features['same_srv_rate']

        # Host-based features
        host_info = self.host_connections[dst_ip]
        host_info['connections'].append({
            'time': current_time,
            'service': service_code,
            'src_port': src_port
        })
        
        host_info['connections'] = [c for c in host_info['connections'] 
                                   if current_time - c['time'] < self.time_window]
        
        features['dst_host_count'] = min(255, len(host_info['connections']))
        
        if features['dst_host_count'] > 0:
            same_srv = sum(1 for c in host_info['connections'] if c['service'] == service_code)
            features['dst_host_srv_count'] = same_srv
            features['dst_host_same_srv_rate'] = same_srv / features['dst_host_count']
            features['dst_host_diff_srv_rate'] = 1.0 - features['dst_host_same_srv_rate']
            
            same_src_port = sum(1 for c in host_info['connections'] if c['src_port'] == src_port)
            features['dst_host_same_src_port_rate'] = same_src_port / features['dst_host_count']
            
            features['dst_host_serror_rate'] = features['serror_rate']
            features['dst_host_srv_serror_rate'] = features['srv_serror_rate']
            features['dst_host_rerror_rate'] = features['rerror_rate']
            features['dst_host_srv_rerror_rate'] = features['srv_rerror_rate']

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
        except:
            pass

    def start_capture(self, interface=None):
        if self.is_capturing:
            return
        
        self.is_capturing = True
        
        if not interface or interface == "":
            interface = None

        def capture():
            try:
                print(f"[*] Starting packet capture on: {interface if interface else 'all interfaces'}")
                sniff(prn=self.packet_callback, store=False, iface=interface, 
                      promisc=True,
                      stop_filter=lambda x: not self.is_capturing)
            except Exception as e:
                print(f"[!] Capture error: {e}")
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
        self.host_connections.clear()
        self.packet_count = 0
