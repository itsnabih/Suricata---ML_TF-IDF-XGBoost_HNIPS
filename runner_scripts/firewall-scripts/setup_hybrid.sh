#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LOG_DIR="$SCRIPT_DIR/saved_logs/firewall"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/log-nomor 3_setup_hybrid.txt"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "[LOG] Logging dimulai: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[LOG] File log: $LOG_FILE"

TARGET_IP="172.17.0.2"
TARGET_PORT="80"
SURICATA_QUEUE="2"
ML_QUEUE="3"
SURICATA_CONF="/etc/suricata/suricata.yaml"

echo ""
echo "     SETUP IPTABLES: SKENARIO 3 - HYBRID (Cascade)         "
echo "  Flow: Attacker -> MANGLE/Suricata(Q2) -> FILTER/ML(Q3)     "
echo ""

echo "[1/4] Mengaktifkan route-queue Suricata (agar paket diteruskan ke ML setelah ACCEPT)..."
sudo sed -i 's/#  route-queue: 3/  route-queue: 3/' "$SURICATA_CONF" 2>/dev/null
echo "      OK route-queue: 3 diaktifkan di suricata.yaml"
 
echo "[2/4] Menerapkan Garda PERTAMA: Suricata di tabel MANGLE (Queue $SURICATA_QUEUE)..."
sudo iptables -t mangle -I OUTPUT -p tcp -d "$TARGET_IP" --dport "$TARGET_PORT" -j NFQUEUE --queue-num "$SURICATA_QUEUE"
sudo iptables -t mangle -I INPUT  -p tcp -s "$TARGET_IP" --sport "$TARGET_PORT" -j NFQUEUE --queue-num "$SURICATA_QUEUE"
echo "      OK [MANGLE] OUTPUT -> NFQUEUE $SURICATA_QUEUE (Suricata)"
echo "      OK [MANGLE] INPUT  ← NFQUEUE $SURICATA_QUEUE (Suricata)"

echo "[3/4] Menerapkan Garda KEDUA: ML di tabel FILTER (Queue $ML_QUEUE)..."
sudo iptables -t filter -I OUTPUT -p tcp -d "$TARGET_IP" --dport "$TARGET_PORT" -j NFQUEUE --queue-num "$ML_QUEUE"
sudo iptables -t filter -I INPUT  -p tcp -s "$TARGET_IP" --sport "$TARGET_PORT" -j NFQUEUE --queue-num "$ML_QUEUE"
echo "      OK [FILTER] OUTPUT -> NFQUEUE $ML_QUEUE (ML Runner)"
echo "      OK [FILTER] INPUT  ← NFQUEUE $ML_QUEUE (ML Runner)"

echo "[4/4] Verifikasi kedua tabel iptables:"
echo ""
echo "  --- TABEL MANGLE (Garda 1: Suricata) ---"
sudo iptables -t mangle -L -v -n --line-numbers | grep -E "NFQUEUE|Chain" | head -10
echo ""
echo "  --- TABEL FILTER (Garda 2: ML Runner) ---"
sudo iptables -t filter -L -v -n --line-numbers | grep -E "NFQUEUE|Chain" | head -10

echo ""
echo "[OK]  IPTables Skenario 3 (Hybrid) berhasil dikonfigurasi!"
echo "    Jalankan: firewall-scripts/run_suricata.sh di Terminal 1"
echo "    Jalankan: firewall-scripts/run_ml.sh di Terminal 2"
echo ""
