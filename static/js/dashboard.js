let isCapturing = false;
let updateInterval = null;
let startTime = null;

document.addEventListener('DOMContentLoaded', function () {
    console.log('Dashboard initializing...');

    // Load interfaces
    loadInterfaces();

    // Attach button listeners
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const clearBtn = document.getElementById('clear-btn');
    const sendAlertBtn = document.getElementById('send-alert');

    if (startBtn) {
        startBtn.addEventListener('click', function () {
            startCapture();
        });
    }

    if (stopBtn) {
        stopBtn.addEventListener('click', function () {
            stopCapture();
        });
    }

    if (clearBtn) {
        clearBtn.addEventListener('click', function () {
            clearStats();
        });
    }

    if (sendAlertBtn) {
        sendAlertBtn.addEventListener('click', function () {
            sendAlert();
        });
    }
});

function loadInterfaces() {
    fetch('/api/get_interfaces')
        .then(response => response.json())
        .then(data => {
            const select = document.getElementById('interface-select');
            if (select && data.interfaces) {
                // Clear loading option
                select.innerHTML = '';

                // Add "All Interfaces" option
                const allOption = document.createElement('option');
                allOption.value = "";
                allOption.textContent = "All Interfaces";
                select.appendChild(allOption);

                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface;
                    option.textContent = iface;
                    select.appendChild(option);
                });
            }
        })
        .catch(error => {
            console.error('Error loading interfaces:', error);
            const select = document.getElementById('interface-select');
            if (select) select.innerHTML = '<option>Error loading interfaces</option>';
        });
}

function startCapture() {
    const select = document.getElementById('interface-select');
    const interface = select ? select.value : '';

    fetch('/api/start_capture', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: interface })
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                isCapturing = true;
                startTime = Date.now();

                // Update UI
                document.getElementById('start-btn').disabled = true;
                document.getElementById('stop-btn').disabled = false;
                document.getElementById('status-text').textContent = 'Monitoring Active';
                document.getElementById('status-dot').className = 'status-dot active';

                // Start updating
                if (updateInterval) clearInterval(updateInterval);
                updateInterval = setInterval(updateDashboard, 2000);
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
    fetch('/api/stop_capture', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                isCapturing = false;

                // Update UI
                document.getElementById('start-btn').disabled = false;
                document.getElementById('stop-btn').disabled = true;
                document.getElementById('status-text').textContent = 'System Idle';
                document.getElementById('status-dot').className = 'status-dot idle';

                // Stop updating
                if (updateInterval) {
                    clearInterval(updateInterval);
                    updateInterval = null;
                }
            }
        })
        .catch(error => {
            console.error('Error stopping capture:', error);
        });
}

function clearStats() {
    if (!confirm('Clear all statistics?')) return;

    fetch('/api/clear_stats', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
        .then(response => response.json())
        .then(data => {
            // Reset UI
            document.getElementById('total-packets').textContent = '0';
            document.getElementById('normal-packets').textContent = '0';
            document.getElementById('attacks-detected').textContent = '0';
            document.getElementById('uptime').textContent = '00:00:00';

            const noDataHtml = `
            <div class="no-data">
                <i class="fa-solid fa-satellite-dish"></i>
                <p>Waiting for network traffic...</p>
            </div>`;

            document.getElementById('packets-container').innerHTML = noDataHtml;

            const noThreatsHtml = `
            <div class="no-data">
                <i class="fa-solid fa-check-circle"></i>
                <p>No threats detected</p>
            </div>`;

            document.getElementById('attack-log-container').innerHTML = noThreatsHtml;

            startTime = Date.now();
        })
        .catch(error => {
            console.error('Error clearing stats:', error);
        });
}

function updateDashboard() {
    fetch('/api/get_packets')
        .then(response => response.json())
        .then(data => {
            updateStats(data.stats);
            updatePackets(data.packets);
            updateAttackLog(data.recent_attacks);
            updateUptime();
        })
        .catch(error => console.error('Error fetching packets:', error));

    fetch('/api/get_system_stats')
        .then(response => response.json())
        .then(data => updateSystemStats(data))
        .catch(error => console.error('Error fetching system stats:', error));
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
        if (isCapturing && container.querySelector('.no-data')) {
            // Keep waiting message
        } else if (!isCapturing && packets.length === 0) {
            container.innerHTML = `
                <div class="no-data">
                    <i class="fa-solid fa-satellite-dish"></i>
                    <p>Waiting for network traffic...</p>
                </div>`;
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
        const conf = packet.confidence ? (packet.confidence * 100).toFixed(1) : '0';

        const badgeClass = packet.is_attack ? 'packet-badge attack' : 'packet-badge normal';
        const icon = packet.is_attack ? '<i class="fa-solid fa-triangle-exclamation"></i>' : '<i class="fa-solid fa-check"></i>';

        div.innerHTML = `
            <div class="packet-header">
                <span class="${badgeClass}">
                    ${icon} ${packet.prediction}
                </span>
                <span class="packet-time">${timestamp}</span>
            </div>
            <div class="packet-details">
                <div class="detail-row">
                    <span class="detail-label">SRC:</span>
                    <span class="detail-value">${src}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">DST:</span>
                    <span class="detail-value">${dst}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">PROTO:</span>
                    <span class="detail-value">${proto.toUpperCase()}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">CONF:</span>
                    <span class="detail-value">${conf}%</span>
                </div>
            </div>
        `;

        container.appendChild(div);
    });
}

function updateAttackLog(attacks) {
    const container = document.getElementById('attack-log-container');

    if (!attacks || attacks.length === 0) {
        container.innerHTML = `
            <div class="no-data">
                <i class="fa-solid fa-check-circle"></i>
                <p>No threats detected</p>
            </div>`;
        return;
    }

    container.innerHTML = '';

    attacks.slice().reverse().forEach(attack => {
        const div = document.createElement('div');
        div.className = 'packet-item attack';

        const conf = attack.confidence ? (attack.confidence * 100).toFixed(1) : '0';

        div.innerHTML = `
            <div class="packet-header">
                <span class="packet-badge attack">
                    <i class="fa-solid fa-bug"></i> THREAT DETECTED
                </span>
                <span class="packet-time">${attack.timestamp}</span>
            </div>
            <div class="packet-details">
                <div class="detail-row">
                    <span class="detail-label">SRC:</span>
                    <span class="detail-value">${attack.src}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">DST:</span>
                    <span class="detail-value">${attack.dst}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">PROTO:</span>
                    <span class="detail-value">${attack.proto.toUpperCase()}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">CONF:</span>
                    <span class="detail-value">${conf}%</span>
                </div>
            </div>
        `;

        container.appendChild(div);
    });
}

function updateUptime() {
    if (startTime) {
        const elapsed = Math.floor((Date.now() - startTime) / 1000);
        const h = Math.floor(elapsed / 3600).toString().padStart(2, '0');
        const m = Math.floor((elapsed % 3600) / 60).toString().padStart(2, '0');
        const s = (elapsed % 60).toString().padStart(2, '0');

        document.getElementById('uptime').textContent = `${h}:${m}:${s}`;
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

// Simple Alert Function
function sendAlert() {
    fetch('/api/alert/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
        .then(response => response.json())
        .then(result => {
            if (result.status === 'success') {
                alert('✅ Alert sent successfully!\n\nA Telegram message has been sent with details of the most recent detected threat.');
            } else if (result.status === 'info') {
                alert('ℹ️ ' + result.message);
            } else {
                alert('❌ Failed to send alert: ' + (result.message || 'Unknown error'));
            }
        })
        .catch(error => {
            alert('❌ Failed to send alert');
            console.error('Error sending alert:', error);
        });
}
