let isCapturing = false;
let updateInterval = null;
let startTime = null;

document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard initializing...');
    
    // Load interfaces
    loadInterfaces();
    
    // Attach button listeners
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const clearBtn = document.getElementById('clear-btn');
    
    if (startBtn) {
        startBtn.addEventListener('click', function() {
            console.log('Start button clicked');
            startCapture();
        });
    }
    
    if (stopBtn) {
        stopBtn.addEventListener('click', function() {
            console.log('Stop button clicked');
            stopCapture();
        });
    }
    
    if (clearBtn) {
        clearBtn.addEventListener('click', function() {
            console.log('Clear button clicked');
            clearStats();
        });
    }
    
    console.log('Dashboard ready');
});

function loadInterfaces() {
    fetch('/api/get_interfaces')
        .then(response => response.json())
        .then(data => {
            const select = document.getElementById('interface-select');
            if (select && data.interfaces) {
                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface;
                    option.textContent = iface;
                    select.appendChild(option);
                });
                console.log('Loaded interfaces:', data.interfaces);
            }
        })
        .catch(error => {
            console.error('Error loading interfaces:', error);
        });
}

function startCapture() {
    const select = document.getElementById('interface-select');
    const interface = select ? select.value : '';
    
    console.log('Starting capture on interface:', interface);
    
    fetch('/api/start_capture', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ interface: interface })
    })
    .then(response => response.json())
    .then(data => {
        console.log('Start response:', data);
        
        if (data.status === 'success') {
            isCapturing = true;
            startTime = Date.now();
            
            // Update UI
            document.getElementById('start-btn').disabled = true;
            document.getElementById('stop-btn').disabled = false;
            document.getElementById('status-text').textContent = 'Status: Monitoring';
            document.getElementById('status-dot').className = 'status-dot active';
            
            // Start updating
            if (updateInterval) {
                clearInterval(updateInterval);
            }
            updateInterval = setInterval(updateDashboard, 2000);
            
            console.log('Monitoring started successfully');
        } else {
            alert('Error: ' + data.message);
        }
    })
    .catch(error => {
        console.error('Error starting capture:', error);
        alert('Error starting capture. Check console.');
    });
}

function stopCapture() {
    console.log('Stopping capture...');
    
    fetch('/api/stop_capture', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        console.log('Stop response:', data);
        
        if (data.status === 'success') {
            isCapturing = false;
            
            // Update UI
            document.getElementById('start-btn').disabled = false;
            document.getElementById('stop-btn').disabled = true;
            document.getElementById('status-text').textContent = 'Status: Stopped';
            document.getElementById('status-dot').className = 'status-dot idle';
            
            // Stop updating
            if (updateInterval) {
                clearInterval(updateInterval);
                updateInterval = null;
            }
            
            console.log('Monitoring stopped');
        }
    })
    .catch(error => {
        console.error('Error stopping capture:', error);
    });
}

function clearStats() {
    if (!confirm('Clear all statistics?')) {
        return;
    }
    
    console.log('Clearing stats...');
    
    fetch('/api/clear_stats', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => response.json())
    .then(data => {
        console.log('Clear response:', data);
        
        // Reset UI
        document.getElementById('total-packets').textContent = '0';
        document.getElementById('normal-packets').textContent = '0';
        document.getElementById('attacks-detected').textContent = '0';
        document.getElementById('uptime').textContent = '0s';
        document.getElementById('packets-container').innerHTML = '<p class="no-data">No packets captured yet.</p>';
        document.getElementById('attack-log-container').innerHTML = '<p class="no-data">No attacks detected</p>';
        
        startTime = Date.now();
        console.log('Stats cleared');
    })
    .catch(error => {
        console.error('Error clearing stats:', error);
    });
}

function updateDashboard() {
    // Fetch packets
    fetch('/api/get_packets')
        .then(response => response.json())
        .then(data => {
            updateStats(data.stats);
            updatePackets(data.packets);
            updateAttackLog(data.recent_attacks);
            updateUptime();
        })
        .catch(error => {
            console.error('Error fetching packets:', error);
        });
    
    // Fetch system stats
    fetch('/api/get_system_stats')
        .then(response => response.json())
        .then(data => {
            updateSystemStats(data);
        })
        .catch(error => {
            console.error('Error fetching system stats:', error);
        });
}

function updateStats(stats) {
    if (!stats) return;
    
    document.getElementById('total-packets').textContent = stats.total_packets || 0;
    document.getElementById('normal-packets').textContent = stats.normal_packets || 0;
    document.getElementById('attacks-detected').textContent = stats.attacks_detected || 0;
}

function updatePackets(packets) {
    const container = document.getElementById('packets-container');
    
    if (!packets || packets.length === 0) {
        if (isCapturing) {
            container.innerHTML = '<p class="no-data">Waiting for packets...</p>';
        }
        return;
    }
    
    container.innerHTML = '';
    
    // Show last 10 packets
    const packetsToShow = packets.slice(-10).reverse();
    
    packetsToShow.forEach(packet => {
        const div = document.createElement('div');
        div.className = packet.is_attack ? 'packet-item attack' : 'packet-item';
        
        const timestamp = new Date(packet.timestamp * 1000).toLocaleTimeString();
        const src = (packet.raw_info && packet.raw_info.src) || 'unknown';
        const dst = (packet.raw_info && packet.raw_info.dst) || 'unknown';
        const proto = (packet.raw_info && packet.raw_info.proto) || 'unknown';
        const conf = packet.confidence ? (packet.confidence * 100).toFixed(2) : '0';
        
        div.innerHTML = `
            <div class="packet-header">
                <span class="packet-type ${packet.is_attack ? 'attack' : 'normal'}">
                    ${packet.prediction}
                </span>
                <span>${timestamp}</span>
            </div>
            <div class="packet-details">
                <p><strong>Source:</strong> ${src}</p>
                <p><strong>Destination:</strong> ${dst}</p>
                <p><strong>Protocol:</strong> ${proto.toUpperCase()}</p>
                <p><strong>Confidence:</strong> <span class="confidence">${conf}%</span></p>
            </div>
        `;
        
        container.appendChild(div);
    });
}

function updateAttackLog(attacks) {
    const container = document.getElementById('attack-log-container');
    
    if (!attacks || attacks.length === 0) {
        container.innerHTML = '<p class="no-data">No attacks detected</p>';
        return;
    }
    
    container.innerHTML = '';
    
    attacks.slice().reverse().forEach(attack => {
        const div = document.createElement('div');
        div.className = 'packet-item attack';
        
        const conf = attack.confidence ? (attack.confidence * 100).toFixed(2) : '0';
        
        div.innerHTML = `
            <div class="packet-header">
                <span class="packet-type attack">ATTACK</span>
                <span>${attack.timestamp}</span>
            </div>
            <div class="packet-details">
                <p><strong>Source:</strong> ${attack.src}</p>
                <p><strong>Destination:</strong> ${attack.dst}</p>
                <p><strong>Protocol:</strong> ${attack.proto.toUpperCase()}</p>
                <p><strong>Confidence:</strong> <span class="confidence">${conf}%</span></p>
            </div>
        `;
        
        container.appendChild(div);
    });
}

function updateUptime() {
    if (startTime) {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        const h = Math.floor(elapsed / 3600);
        const m = Math.floor((elapsed % 3600) / 60);
        const s = elapsed % 60;
        
        let uptime = '';
        if (h > 0) uptime += h + 'h ';
        if (m > 0) uptime += m + 'm ';
        uptime += s + 's';
        
        document.getElementById('uptime').textContent = uptime;
    }
}

function updateSystemStats(stats) {
    if (!stats) return;
    
    if (stats.cpu !== undefined) {
        const cpuBar = document.getElementById('cpu-bar');
        const cpuText = document.getElementById('cpu-text');
        if (cpuBar) cpuBar.style.width = stats.cpu + '%';
        if (cpuText) cpuText.textContent = stats.cpu.toFixed(1) + '%';
    }
    
    if (stats.memory && stats.memory.percent !== undefined) {
        const memBar = document.getElementById('memory-bar');
        const memText = document.getElementById('memory-text');
        if (memBar) memBar.style.width = stats.memory.percent + '%';
        if (memText) memText.textContent = stats.memory.percent.toFixed(1) + '%';
    }
}

console.log('Dashboard script loaded');
