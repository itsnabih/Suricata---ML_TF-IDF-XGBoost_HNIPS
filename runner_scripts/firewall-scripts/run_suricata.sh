#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LOG_DIR="$SCRIPT_DIR/saved_logs/firewall"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/log-nomor 4_run_suricata.txt"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "[LOG] Logging dimulai: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[LOG] File log: $LOG_FILE"

SURICATA_CONF="/etc/suricata/suricata.yaml"
FAST_LOG="/var/log/suricata/fast.log"
QUEUE_NUM="2"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   NODE FIREWALL 1: SURICATA RUNNER   ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo " Suricata akan menginspeksi traffic di NFQUEUE $QUEUE_NUM"
echo " Alert akan ditampilkan secara real-time di bawah ini."
echo " Tekan Ctrl+C untuk menghentikan monitoring."
echo ""
echo "───────────────────────────────────────"

sudo pkill -x suricata 2>/dev/null
sleep 1

sudo suricata -c "$SURICATA_CONF" -q "$QUEUE_NUM" > /dev/null 2>&1 &
SURICATA_PID=$!
echo "[+] Suricata berjalan (PID: $SURICATA_PID), menunggu inisialisasi (5 detik)..."
sleep 5

if ! kill -0 "$SURICATA_PID" 2>/dev/null; then
    echo "[!] ERROR: Suricata gagal berjalan! Periksa log:"
    echo "    sudo tail -n 30 /var/log/suricata/suricata.log"
    exit 1
fi

echo "[✓] Suricata aktif. Memantau alert real-time dari: $FAST_LOG"
echo "═══════════════════════════════════════"
echo ""

cleanup() {
    echo ""
    echo "==================================================="
    echo " [!] MENGHENTIKAN SURICATA & MENGAMBIL STATISTIK"
    echo "==================================================="
    
    kill "$TAIL_PID" 2>/dev/null
    
    if kill -0 "$SURICATA_PID" 2>/dev/null; then
        sudo kill -SIGUSR1 "$SURICATA_PID"
        sleep 1
        sudo pkill -x suricata
    fi

    DROPS=$(sudo grep -cv '^\s*$' "$FAST_LOG" 2>/dev/null || echo 0)
    
    TOTAL=$(sudo awk '/decoder.pkts/ {val=$NF} END {print val}' /var/log/suricata/stats.log 2>/dev/null)
    TOTAL=${TOTAL:-0}
    
    if [ "$TOTAL" -lt "$DROPS" ]; then TOTAL="$DROPS"; fi
    
    ACCEPTS=$((TOTAL - DROPS))

    echo ""
    echo " RINGKASAN TRAFFIC SURICATA (Skenario $QUEUE_NUM)"
    echo " -------------------------------------------------"
    echo " Total Paket Terinspeksi : $TOTAL paket"
    echo " Paket di-ACCEPT (Lolos) : $ACCEPTS paket"
    echo " Paket di-DROP (Ditolak) : $DROPS paket"
    echo "==================================================="
    exit 0
}

trap cleanup SIGINT SIGTERM

tail -f "$FAST_LOG" &
TAIL_PID=$!

wait "$TAIL_PID"
