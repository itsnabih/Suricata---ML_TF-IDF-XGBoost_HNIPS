#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LOG_DIR="$SCRIPT_DIR/saved_logs/firewall"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/log-nomor 6_cleanup.txt"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "[LOG] Logging dimulai: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[LOG] File log: $LOG_FILE"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

echo ""
echo "         CLEANUP / RESET ENV          "
echo ""

echo "[1/4] Mematikan proses Suricata..."
sudo pkill -x suricata 2>/dev/null && echo "      OK Suricata dihentikan." || echo "      - Suricata tidak berjalan."

echo "[2/4] Mematikan proses ML Runner..."
sudo pkill -f model_ML_run.py 2>/dev/null && echo "      OK ML Runner dihentikan." || echo "      - ML Runner tidak berjalan."

echo "[3/4] Membersihkan iptables tabel FILTER..."
sudo iptables -t filter -F
echo "      OK Tabel filter bersih."

echo "[4/4] Membersihkan iptables tabel MANGLE..."
sudo iptables -t mangle -F
echo "      OK Tabel mangle bersih."

echo ""
echo "[OK]  Cleanup selesai. Environment siap untuk skenario baru."
echo ""
