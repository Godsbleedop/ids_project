from flask import Flask, render_template, jsonify, request
from packet_capture import PacketCapture
from ids_detector import IDSDetector
import psutil
import time
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

packet_capture = PacketCapture()
ids_detector = IDSDetector()

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
        data = request.json
        interface = data.get('interface', None) if data else None
        if interface == "":
            interface = "lo"
        print(f"Starting capture with interface: {interface}")
        if packet_capture.is_capturing:
            return jsonify({'status': 'error', 'message': 'Already capturing'})
        
        packet_capture.start_capture(interface)
        print(f"Capture started on interface: {interface}")
        return jsonify({'status': 'success', 'message': 'Capture started'})
    except Exception as e:
        print(f"Error starting capture: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/stop_capture', methods=['POST'])
def stop_capture():
    try:
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
        recent_packets = packet_capture.get_recent_packets(20)
        
        if not recent_packets:
            return jsonify({
                'packets': [],
                'stats': stats,
                'is_capturing': packet_capture.is_capturing
            })
        
        results = ids_detector.predict_batch(recent_packets)
        
        for result in results:
            if result['is_attack']:
                stats['attacks_detected'] += 1
                
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
        
        stats['total_packets'] = packet_capture.packet_count
        
        return jsonify({
            'packets': results[-10:],
            'stats': stats,
            'is_capturing': packet_capture.is_capturing,
            'recent_attacks': attack_log[-5:]
        })
        
    except Exception as e:
        print(f"Error in get_packets: {e}")
        return jsonify({
            'packets': [],
            'stats': stats,
            'is_capturing': packet_capture.is_capturing,
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
    packet_capture.clear_data()
    print("Statistics cleared")
    return jsonify({'status': 'success', 'message': 'Statistics cleared'})

if __name__ == '__main__':
    print("=" * 50)
    print("Starting IDS Dashboard...")
    print("=" * 50)
    print("Access the dashboard at: http://localhost:5000")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
