"""
Threat Classification System
Identifies specific attack types from network features
"""

class ThreatClassifier:
    def __init__(self):
        self.threat_types = {
            'SYN_FLOOD': 'SYN Flood Attack',
            'PORT_SCAN': 'Port Scanning',
            'DOS': 'Denial of Service',
            'DDOS': 'Distributed DoS',
            'BRUTE_FORCE': 'Brute Force Attack',
            'LAND_ATTACK': 'Land Attack',
            'PROBE': 'Network Probing',
            'BACKDOOR': 'Backdoor Detection',
            'UNKNOWN': 'Unknown Attack'
        }
    
    def classify_threat(self, features):
        """
        Classify the specific type of attack based on packet features
        Returns: (threat_type, severity, description)
        """
        # Land attack - CRITICAL
        if features.get('land', 0) == 1:
            return (
                'LAND_ATTACK',
                'CRITICAL',
                'Same source/destination IP detected - typical of Land attacks'
            )
        
        # SYN Flood detection - HIGH
        serror_rate = features.get('serror_rate', 0)
        count = features.get('count', 0)
        syn_flags = features.get('flag', '') == 'S0'
        
        if serror_rate > 0.7 and count > 80 and syn_flags:
            return (
                'SYN_FLOOD',
                'HIGH',
                f'High SYN error rate ({serror_rate:.2f}) with {count} connections'
            )
        
        # Port Scanning - MEDIUM to HIGH
        dst_host_count = features.get('dst_host_count', 0)
        dst_host_same_srv_rate = features.get('dst_host_same_srv_rate', 1.0)
        same_srv_rate = features.get('same_srv_rate', 1.0)
        
        if dst_host_count > 40 and dst_host_same_srv_rate < 0.25:
            severity = 'HIGH' if dst_host_count > 100 else 'MEDIUM'
            return (
                'PORT_SCAN',
                severity,
                f'Port scanning detected: {dst_host_count} hosts contacted'
            )
        
        # Distributed DoS - CRITICAL
        if count > 200 and dst_host_count > 50:
            return (
                'DDOS',
                'CRITICAL',
                f'DDoS pattern: {count} connections from {dst_host_count} hosts'
            )
        
        # DoS Attack - HIGH
        if count > 150:
            return (
                'DOS',
                'HIGH',
                f'High connection rate: {count} connections in time window'
            )
        
        # Brute Force - MEDIUM
        service = features.get('service', '')
        logged_in = features.get('logged_in', 0)
        rerror_rate = features.get('rerror_rate', 0)
        
        if service in ['ssh', 'ftp', 'telnet'] and rerror_rate > 0.6 and count > 20:
            return (
                'BRUTE_FORCE',
                'MEDIUM',
                f'Possible brute force on {service.upper()}: {count} failed attempts'
            )
        
        # Network Probing - LOW to MEDIUM
        dst_host_diff_srv_rate = features.get('dst_host_diff_srv_rate', 0)
        if dst_host_diff_srv_rate > 0.5 and dst_host_count > 20:
            return (
                'PROBE',
                'MEDIUM',
                f'Network reconnaissance: Multiple services probed'
            )
        
        # Unknown attack type
        return (
            'UNKNOWN',
            'LOW',
            'Suspicious activity detected but type unclear'
        )
    
    def get_threat_details(self, threat_type, features):
        """
        Get detailed information about the threat
        """
        details = {
            'type': self.threat_types.get(threat_type, 'Unknown'),
            'source_ip': features.get('src_ip', 'unknown'),
            'destination_ip': features.get('dst_ip', 'unknown'),
            'protocol': features.get('protocol_type', 'unknown'),
            'service': features.get('service', 'unknown'),
            'connection_count': features.get('count', 0),
            'packet_size': features.get('src_bytes', 0)
        }
        return details

