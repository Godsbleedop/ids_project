from flask import Flask, render_template, jsonify, request
import psutil
import time
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Import with error handling
try:
    from packet_capture import PacketCapture
    packet_capture = PacketCapture()
    print("Packet capture module loaded")
except Exception as e:
    print(f"ERROR loading packet_capture: {e}")
    packet_capture = None

try:
    from ids_detector import IDSDetector
    ids_detector = IDSDetector()
    print("IDS detector loaded")
except Exception as e:
    print(f"ERROR loading ids_detector: {e}")
    ids_detector = None

attack_log = []
stats = {
    'total_packets': 0,
    'attacks_detected': 0,
    'normal_packets': 0,
    'start_time': time.time()
}

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/start_capture', methods=['POST'])
def start_capture():
    try:
        if packet_capture is None:
            return jsonify({'status': 'error', 'message': 'Packet capture not available'})
        
        data = request.json
        interface = data.get('interface', None) if data else None
        
        if interface == "":
            interface = None
        
        print(f"Starting capture with interface: {interface}")
        
        if packet_capture.is_capturing:
            return jsonify({'status': 'error', 'message': 'Already capturing'})
        
        packet_capture.start_capture(interface)
        print(f"Capture started successfully")
        return jsonify({'status': 'success', 'message': 'Capture started'})
    except Exception as e:
        print(f"Error starting capture: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/stop_capture', methods=['POST'])
def stop_capture():
    try:
        if packet_capture is None:
            return jsonify({'status': 'error', 'message': 'Packet capture not available'})
        
        packet_capture.stop_capture()
        print("Capture stopped")
        return jsonify({'status': 'success', 'message': 'Capture stopped'})
    except Exception as e:
        print(f"Error stopping capture: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/get_interfaces', methods=['GET'])
def get_interfaces():
    try:
        interfaces = list(psutil.net_if_addrs().keys())
        print(f"Available interfaces: {interfaces}")
        return jsonify({'interfaces': interfaces})
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        return jsonify({'interfaces': []})

@app.route('/api/get_packets', methods=['GET'])
def get_packets():
    try:
        if packet_capture is None or ids_detector is None:
            return jsonify({
                'packets': [],
                'stats': stats,
                'is_capturing': False,
                'error': 'System not initialized'
            })
        
        recent_packets = packet_capture.get_recent_packets(20)
        
        if not recent_packets:
            return jsonify({
                'packets': [],
                'stats': stats,
                'is_capturing': packet_capture.is_capturing
            })
        
        results = ids_detector.predict_batch(recent_packets)
        
        attack_count = 0
        for result in results:
            if result['is_attack']:
                stats['attacks_detected'] += 1
                attack_count += 1
                
                attack_entry = {
                    'timestamp': datetime.fromtimestamp(result['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
                    'src': result['raw_info'].get('src', 'unknown'),
                    'dst': result['raw_info'].get('dst', 'unknown'),
                    'proto': result['raw_info'].get('proto', 'unknown'),
                    'confidence': result['confidence']
                }
                
                attack_log.append(attack_entry)
                
                if len(attack_log) > 100:
                    attack_log.pop(0)
            else:
                stats['normal_packets'] += 1
        
        if attack_count > 0:
            print(f"ATTACKS DETECTED: {attack_count} attacks in this batch")
        
        stats['total_packets'] = packet_capture.packet_count
        
        return jsonify({
            'packets': results[-10:],
            'stats': {
                'total_packets': int(stats['total_packets']),
                'attacks_detected': int(stats['attacks_detected']),
                'normal_packets': int(stats['normal_packets']),
                'start_time': float(stats['start_time'])
            },
            'is_capturing': bool(packet_capture.is_capturing),
            'recent_attacks': attack_log[-5:]
        })
        
    except Exception as e:
        print(f"Error in get_packets: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'packets': [],
            'stats': stats,
            'is_capturing': packet_capture.is_capturing if packet_capture else False,
            'error': str(e)
        })

@app.route('/api/get_system_stats', methods=['GET'])
def get_system_stats():
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        
        return jsonify({
            'cpu': cpu_percent,
            'memory': {
                'percent': memory.percent,
                'used': memory.used / (1024**3),
                'total': memory.total / (1024**3)
            }
        })
    except Exception as e:
        print(f"Error getting system stats: {e}")
        return jsonify({'error': str(e)})

@app.route('/api/get_attack_log', methods=['GET'])
def get_attack_log():
    return jsonify({'attacks': attack_log})

@app.route('/api/clear_stats', methods=['POST'])
def clear_stats():
    global stats, attack_log
    stats = {
        'total_packets': 0,
        'attacks_detected': 0,
        'normal_packets': 0,
        'start_time': time.time()
    }
    attack_log = []
    if packet_capture:
        packet_capture.clear_data()
    print("Statistics cleared")
    return jsonify({'status': 'success', 'message': 'Statistics cleared'})

if __name__ == '__main__':
    print("=" * 50)
    print("Starting IDS Dashboard...")
    print("=" * 50)
    if ids_detector and ids_detector.model_loaded:
        print("Running with ML-based detection")
    else:
        print("Running with RULE-based detection (sklearn not available)")
    print("Access the dashboard at: http://localhost:5000")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
