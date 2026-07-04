#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LOG_DIR="$SCRIPT_DIR/saved_logs/target"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/log-nomor 1_monitor_iptables.txt"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "[LOG] Logging dimulai: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[LOG] File log: $LOG_FILE"

INTERVAL=2  # refresh setiap N detik

echo ""
echo "     NODE TARGET: IPTABLES PACKET COUNTER (Watch)     "
echo ""
echo "  Memantau jumlah paket yang ditangkap/didrop di tiap tabel."
echo "  Refresh setiap $INTERVAL detik. Tekan Ctrl+C untuk berhenti."
echo ""
echo "  Kolom 'pkts' = jumlah paket yang masuk ke rule tersebut."
echo "  Kolom 'bytes' = total byte data yang diproses."
echo ""
echo "  MANGLE = Garda 1 (Suricata) — hanya aktif di Hybrid"
echo "  FILTER = Garda 2 (ML) — aktif di ML Only & Hybrid"
echo ""

sleep 2

trap 'echo ""; echo "[LOG] Monitor iptables dihentikan: $(date "+%Y-%m-%d %H:%M:%S")"; exit 0' SIGINT SIGTERM

while true; do
    echo "--------------------------------------------------------"
    echo "  IPTABLES PACKET COUNTER — $(date '+%H:%M:%S')"
    echo "--------------------------------------------------------"
    echo ""
    echo "  ── TABEL MANGLE (Garda 1: Suricata) ──────────────"
    sudo iptables -t mangle -L -v -n --line-numbers 2>/dev/null | grep -E "NFQUEUE|pkts|bytes|Chain" || echo "  (Tidak ada rule MANGLE aktif)"
    echo ""
    echo "  ── TABEL FILTER (Garda 2: ML Runner) ─────────────"
    sudo iptables -t filter -L -v -n --line-numbers 2>/dev/null | grep -E "NFQUEUE|pkts|bytes|Chain" || echo "  (Tidak ada rule FILTER aktif)"
    echo ""
    echo "  Tip: Kolom pertama = paket (#pkts), kedua = bytes"
    echo ""
    sleep "$INTERVAL"
done
