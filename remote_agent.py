import time
import requests
import threading
import sys
import argparse
from scapy.all import sniff, IP

# Import PacketCapture to reuse feature extraction logic
# We assume this script is run in the same directory as packet_capture.py
try:
    from packet_capture import PacketCapture
except ImportError:
    print("Error: packet_capture.py not found. Please run this script in the same directory as the IDS project.")
    sys.exit(1)

class RemoteAgent:
    def __init__(self, detector_url, interface=None):
        self.detector_url = detector_url.rstrip('/')
        self.interface = interface
        self.packet_capture = PacketCapture()
        self.packet_buffer = []
        self.is_running = False
        self.lock = threading.Lock()
        
    def packet_callback(self, packet):
        try:
            # Reuse the existing extraction logic
            features = self.packet_capture.extract_features(packet)
            if features:
                packet_info = {
                    "timestamp": float(time.time()),
                    "features": features,
                    "raw_info": {
                        "src": str(packet[IP].src if packet.haslayer(IP) else "unknown"),
                        "dst": str(packet[IP].dst if packet.haslayer(IP) else "unknown"),
                        "proto": str(features["protocol_type"]),
                        "size": int(features["src_bytes"]),
                    },
                }
                
                with self.lock:
                    self.packet_buffer.append(packet_info)
                    
        except Exception:
            pass

    def sender_loop(self):
        """Periodically send buffered packets to the detector"""
        print(f"[*] Starting sender loop to {self.detector_url}")
        while self.is_running:
            time.sleep(1.0) # Send every second
            
            packets_to_send = []
            with self.lock:
                if self.packet_buffer:
                    packets_to_send = self.packet_buffer[:]
                    self.packet_buffer = []
            
            if packets_to_send:
                try:
                    response = requests.post(
                        f"{self.detector_url}/api/ingest_packets",
                        json={"packets": packets_to_send},
                        timeout=2
                    )
                    if response.status_code != 200:
                        print(f"[!] Error sending packets: {response.text}")
                    else:
                        # Optional: print success for debug
                        # print(f"[+] Sent {len(packets_to_send)} packets")
                        pass
                except Exception as e:
                    print(f"[!] Connection error: {e}")

    def start(self):
        self.is_running = True
        
        # Start sender thread
        sender_thread = threading.Thread(target=self.sender_loop, daemon=True)
        sender_thread.start()
        
        print(f"[*] Starting remote capture on interface: {self.interface if self.interface else 'ALL'}")
        
        try:
            sniff(
                prn=self.packet_callback,
                store=False,
                iface=self.interface,
                promisc=True
            )
        except KeyboardInterrupt:
            print("\n[*] Stopping remote agent...")
        except Exception as e:
            print(f"[!] Sniffing error: {e}")
        finally:
            self.is_running = False
            sender_thread.join(timeout=2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDS Remote Agent")
    parser.add_argument("--url", required=True, help="URL of the central IDS (e.g., http://192.168.1.100:5000)")
    parser.add_argument("--interface", help="Network interface to sniff on (optional)")
    
    args = parser.parse_args()
    
    agent = RemoteAgent(args.url, args.interface)
    agent.start()
