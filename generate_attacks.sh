#!/bin/bash

echo "================================================"
echo "GUARANTEED ATTACK TRAFFIC GENERATOR"
echo "================================================"
echo ""
echo "This script generates localhost traffic that"
echo "the IDS can actually capture and analyze."
echo ""
read -p "Press Enter to start (make sure IDS is monitoring)..."

echo ""
echo "Starting attack sequence..."
echo ""

# Start a simple HTTP server in background for targets
python3 -m http.server 8888 > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2

echo "[1/6] Baseline - Normal traffic..."
curl -s http://localhost:8888 > /dev/null
curl -s http://localhost:5000 > /dev/null
echo "   ✓ Normal requests sent"
sleep 3

echo ""
echo "[2/6] Port Scan Attack (High Detection Rate)..."
sudo nmap -sS localhost -p 1-100 --min-rate 100 > /dev/null 2>&1
echo "   ✓ Port scan completed"
sleep 5

echo ""
echo "[3/6] Rapid Connection Attack..."
for i in {1..30}; do
    curl -s --max-time 0.1 http://localhost:8888 > /dev/null 2>&1 &
    curl -s --max-time 0.1 http://localhost:5000 > /dev/null 2>&1 &
done
wait
echo "   ✓ Rapid connections sent"
sleep 5

echo ""
echo "[4/6] SYN Scan (Suspicious Flags)..."
sudo nmap -sS localhost -p 80,443,22,21,25,8888 > /dev/null 2>&1
echo "   ✓ SYN scan completed"
sleep 5

echo ""
echo "[5/6] Failed Connection Attempts..."
for port in {9000..9030}; do
    timeout 0.1 nc -zv localhost $port > /dev/null 2>&1 &
done
wait
echo "   ✓ Failed connections attempted"
sleep 5

echo ""
echo "[6/6] Aggressive Scan..."
sudo nmap -A -T5 localhost -p 1-200 --min-rate 500 > /dev/null 2>&1
echo "   ✓ Aggressive scan completed"

# Cleanup
kill $SERVER_PID 2>/dev/null

echo ""
echo "================================================"
echo "ATTACK GENERATION COMPLETE!"
echo "================================================"
echo ""
echo "Check your dashboard now!"
echo "- You should see attack detections"
echo "- Look for RED badges in Live Packet Analysis"
echo "- Check Recent Attack Alerts panel"
echo ""
