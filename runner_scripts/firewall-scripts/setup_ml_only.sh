#!/bin/bash
# ============================================================
#  firewall-scripts/setup_ml_only.sh
#  Mengatur IPTables untuk Skenario 2: ML Only
#  Semua traffic HTTP ke/dari DVWA dimasukkan ke NFQUEUE 3 (ML)
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Logging Setup ──────────────────────────────────────────────
LOG_DIR="$SCRIPT_DIR/saved_logs/firewall"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/log-nomor 2_setup_ml_only.txt"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "[LOG] Logging dimulai: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[LOG] File log: $LOG_FILE"
# ───────────────────────────────────────────────────────────────

TARGET_IP="172.17.0.2"
TARGET_PORT="80"
QUEUE_NUM="3"

echo ""
echo "    SETUP IPTABLES: SKENARIO 2 - ML ONLY  "
echo ""

echo "[1/2] Menerapkan rule iptables (tabel FILTER -> Queue $QUEUE_NUM)..."
sudo iptables -t filter -I OUTPUT -p tcp -d "$TARGET_IP" --dport "$TARGET_PORT" -j NFQUEUE --queue-num "$QUEUE_NUM"
sudo iptables -t filter -I INPUT  -p tcp -s "$TARGET_IP" --sport "$TARGET_PORT" -j NFQUEUE --queue-num "$QUEUE_NUM"
echo "      OK OUTPUT -> NFQUEUE $QUEUE_NUM (tujuan $TARGET_IP:$TARGET_PORT)"
echo "      OK INPUT  ← NFQUEUE $QUEUE_NUM (sumber $TARGET_IP:$TARGET_PORT)"

echo "[2/2] Verifikasi rule iptables aktif:"
echo ""
sudo iptables -t filter -L -v -n --line-numbers | grep -E "NFQUEUE|Chain" | head -20

echo ""
echo "[OK]  IPTables Skenario 2 (ML Only) berhasil dikonfigurasi!"
echo "    Jalankan: firewall-scripts/run_ml.sh di terminal ini."
echo ""
