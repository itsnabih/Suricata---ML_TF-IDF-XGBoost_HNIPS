#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LOG_DIR="$SCRIPT_DIR/saved_logs/firewall"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/log-nomor 7_reset_logs.txt"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "[LOG] Logging dimulai: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[LOG] File log: $LOG_FILE"

DVWA_CONTAINER="dvwa"

echo ""
echo "           RESET LOG FILES            "
echo ""

echo "[1/4] Menghapus log Suricata (fast.log, eve.json, stats.log)..."
sudo truncate -s 0 /var/log/suricata/fast.log 2>/dev/null   && echo "      OK fast.log dikosongkan."   || echo "      - fast.log tidak ditemukan."
sudo truncate -s 0 /var/log/suricata/eve.json 2>/dev/null   && echo "      OK eve.json dikosongkan."   || echo "      - eve.json tidak ditemukan."
sudo truncate -s 0 /var/log/suricata/stats.log 2>/dev/null  && echo "      OK stats.log dikosongkan."  || echo "      - stats.log tidak ditemukan."

echo ""
echo "[2/4] Menghentikan container DVWA untuk reset log-nya..."
sudo docker stop "$DVWA_CONTAINER" > /dev/null 2>&1 && echo "      OK Container DVWA dihentikan."

echo "[3/4] Mengosongkan log container DVWA..."
CONTAINER_ID=$(sudo docker inspect -f '{{.Id}}' "$DVWA_CONTAINER" 2>/dev/null)
if [ -n "$CONTAINER_ID" ]; then
    LOG_PATH="/var/lib/docker/containers/${CONTAINER_ID}"
    LOG_FILE=$(sudo find "$LOG_PATH" -name '*-json.log' 2>/dev/null | head -1)
    if [ -n "$LOG_FILE" ]; then
        sudo truncate -s 0 "$LOG_FILE"
        echo "      OK Log DVWA dikosongkan: $LOG_FILE"
    else
        echo "      - File log JSON Docker tidak ditemukan."
    fi
else
    echo "      ! Container '$DVWA_CONTAINER' tidak ditemukan."
fi

echo "[4/4] Menghidupkan kembali container DVWA..."
sudo docker start "$DVWA_CONTAINER" > /dev/null 2>&1
echo "      OK Container DVWA dijalankan kembali."
echo ""
echo "[WAIT]  Menunggu DVWA siap melayani request (7 detik)..."
sleep 7

echo ""
echo "[OK]  Reset log selesai. Semua log sudah bersih."
echo ""
