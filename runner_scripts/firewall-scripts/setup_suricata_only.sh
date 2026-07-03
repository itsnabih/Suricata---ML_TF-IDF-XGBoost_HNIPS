#!/bin/bash
# ============================================================
#  firewall-scripts/setup_suricata_only.sh
#  Mengatur IPTables untuk Skenario 1: Suricata Only
#  Semua traffic HTTP ke/dari DVWA dimasukkan ke NFQUEUE 2 (Suricata)
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Logging Setup ──────────────────────────────────────────────
LOG_DIR="$SCRIPT_DIR/saved_logs/firewall"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/log-nomor 1_setup_suricata_only.txt"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "[LOG] Logging dimulai: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[LOG] File log: $LOG_FILE"
# ───────────────────────────────────────────────────────────────

TARGET_IP="172.17.0.2"
TARGET_PORT="80"
QUEUE_NUM="2"
SURICATA_CONF="/etc/suricata/suricata.yaml"

echo ""
echo "  SETUP IPTABLES: SKENARIO 1 - SURICATA   "
echo ""

echo "[1/3] Memastikan route-queue Suricata DINONAKTIFKAN (Suricata Only mode)..."
sudo sed -i 's/^ *route-queue: 3/#  route-queue: 3/' "$SURICATA_CONF" 2>/dev/null
echo "      OK route-queue di suricata.yaml dinonaktifkan."

echo "[2/3] Menerapkan rule iptables (tabel FILTER -> Queue $QUEUE_NUM)..."
sudo iptables -t filter -I OUTPUT -p tcp -d "$TARGET_IP" --dport "$TARGET_PORT" -j NFQUEUE --queue-num "$QUEUE_NUM"
sudo iptables -t filter -I INPUT  -p tcp -s "$TARGET_IP" --sport "$TARGET_PORT" -j NFQUEUE --queue-num "$QUEUE_NUM"
echo "      OK OUTPUT -> NFQUEUE $QUEUE_NUM (tujuan $TARGET_IP:$TARGET_PORT)"
echo "      OK INPUT  ← NFQUEUE $QUEUE_NUM (sumber $TARGET_IP:$TARGET_PORT)"

echo "[3/3] Verifikasi rule iptables aktif:"
echo ""
sudo iptables -t filter -L -v -n --line-numbers | grep -E "NFQUEUE|Chain" | head -20

echo ""
echo "[OK]  IPTables Skenario 1 (Suricata Only) berhasil dikonfigurasi!"
echo "    Jalankan: firewall-scripts/run_suricata.sh di terminal ini."
echo ""
