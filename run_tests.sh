#!/bin/bash

# Configuration
TARGET="http://172.17.0.2/vulnerabilities/sqli/?id=1&Submit=Submit"
COOKIE="PHPSESSID=hdcoukkc72vv9ha0fjeop7g5m6; security=low"
OUT_DIR="data-hasil_pengujian"
DVWA_CONTAINER="dvwa"
SURICATA_CONF="/etc/suricata/suricata.yaml"
ML_SCRIPT="model_ML_run.py"

mkdir -p "$OUT_DIR"/{01_suricata_only,02_ml_only,03_hybrid}/{user,firewall,target}

function cleanup() {
    sudo iptables -F
    sudo pkill -f suricata
    sudo pkill -f model_ML_run.py
    sleep 2
}

function fetch_logs() {
    local scenario_dir=$1
    echo "[*] Fetching logs to $scenario_dir..."
    
    # Target logs
    sudo docker logs "$DVWA_CONTAINER" > "$scenario_dir/target/dvwa_access.log" 2>&1
    
    # Iptables stats
    sudo iptables -L -v -n > "$scenario_dir/firewall/iptables_stats.txt"
    
    # Suricata logs
    if [ -f /var/log/suricata/fast.log ]; then
        sudo cp /var/log/suricata/fast.log "$scenario_dir/firewall/suricata_fast.log"
    fi
    if [ -f /var/log/suricata/eve.json ]; then
        sudo cp /var/log/suricata/eve.json "$scenario_dir/firewall/suricata_eve.json"
    fi
}

function clear_logs() {
    sudo truncate -s 0 /var/log/suricata/fast.log 2>/dev/null || true
    sudo truncate -s 0 /var/log/suricata/eve.json 2>/dev/null || true
}

echo "========================================="
echo " SCENARIO 1: SURICATA ONLY"
echo "========================================="
cleanup
clear_logs
# Disable route-queue in suricata.yaml
sudo sed -i 's/^ *route-queue: 3/#  route-queue: 3/' "$SURICATA_CONF"

sudo iptables -I OUTPUT -p tcp -d 172.17.0.2 --dport 80 -j NFQUEUE --queue-num 2
sudo iptables -I INPUT -p tcp -s 172.17.0.2 --sport 80 -j NFQUEUE --queue-num 2

sudo suricata -c "$SURICATA_CONF" -q 2 > "$OUT_DIR/01_suricata_only/firewall/suricata_stdout.log" 2>&1 &
SURICATA_PID=$!
sleep 5

echo "[*] Running SQLMap..."
sqlmap -u "$TARGET" --cookie="$COOKIE" -p id --random-agent --batch --level=2 --risk=2 > "$OUT_DIR/01_suricata_only/user/sqlmap.log" 2>&1
echo "[*] Simulating normal traffic..."
curl -s "http://172.17.0.2/vulnerabilities/fi/?page=include.php" -H "Cookie: $COOKIE" > /dev/null

fetch_logs "$OUT_DIR/01_suricata_only"
cleanup

echo "========================================="
echo " SCENARIO 2: ML ONLY"
echo "========================================="
cleanup
clear_logs

sudo iptables -I OUTPUT -p tcp -d 172.17.0.2 --dport 80 -j NFQUEUE --queue-num 3
sudo iptables -I INPUT -p tcp -s 172.17.0.2 --sport 80 -j NFQUEUE --queue-num 3

sudo python3 "$ML_SCRIPT" --queue 3 --log-payloads > "$OUT_DIR/02_ml_only/firewall/ml_stdout.log" 2>&1 &
ML_PID=$!
sleep 5

echo "[*] Running SQLMap..."
sqlmap -u "$TARGET" --cookie="$COOKIE" -p id --random-agent --batch --level=2 --risk=2 > "$OUT_DIR/02_ml_only/user/sqlmap.log" 2>&1
echo "[*] Simulating normal traffic..."
curl -s "http://172.17.0.2/vulnerabilities/fi/?page=include.php" -H "Cookie: $COOKIE" > /dev/null

fetch_logs "$OUT_DIR/02_ml_only"
cleanup

echo "========================================="
echo " SCENARIO 3: HYBRID (Suricata + ML)"
echo "========================================="
cleanup
clear_logs

# Enable route-queue
sudo sed -i 's/#  route-queue: 3/  route-queue: 3/' "$SURICATA_CONF"

sudo iptables -I OUTPUT -p tcp -d 172.17.0.2 --dport 80 -j NFQUEUE --queue-num 2
sudo iptables -I INPUT -p tcp -s 172.17.0.2 --sport 80 -j NFQUEUE --queue-num 2

sudo suricata -c "$SURICATA_CONF" -q 2 > "$OUT_DIR/03_hybrid/firewall/suricata_stdout.log" 2>&1 &
sudo python3 "$ML_SCRIPT" --queue 3 --log-payloads > "$OUT_DIR/03_hybrid/firewall/ml_stdout.log" 2>&1 &
sleep 5

echo "[*] Running SQLMap..."
sqlmap -u "$TARGET" --cookie="$COOKIE" -p id --random-agent --batch --level=2 --risk=2 > "$OUT_DIR/03_hybrid/user/sqlmap.log" 2>&1
echo "[*] Simulating normal traffic..."
curl -s "http://172.17.0.2/vulnerabilities/fi/?page=include.php" -H "Cookie: $COOKIE" > /dev/null

fetch_logs "$OUT_DIR/03_hybrid"
cleanup

echo "[+] All scenarios completed!"
