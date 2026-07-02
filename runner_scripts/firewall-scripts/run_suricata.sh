#!/bin/bash
# ============================================================
#  firewall-scripts/run_suricata.sh
#  Menjalankan Suricata (Q2) dan menampilkan alert real-time.
#  Jalankan SETELAH setup_suricata_only.sh atau setup_hybrid.sh.
# ============================================================

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

# Pastikan Suricata tidak sedang berjalan
sudo pkill -x suricata 2>/dev/null
sleep 1

# Jalankan Suricata di background (queue mode)
sudo suricata -c "$SURICATA_CONF" -q "$QUEUE_NUM" > /dev/null 2>&1 &
SURICATA_PID=$!
echo "[+] Suricata berjalan (PID: $SURICATA_PID), menunggu inisialisasi (5 detik)..."
sleep 5

# Periksa apakah Suricata sukses berjalan
if ! kill -0 "$SURICATA_PID" 2>/dev/null; then
    echo "[!] ERROR: Suricata gagal berjalan! Periksa log:"
    echo "    sudo tail -n 30 /var/log/suricata/suricata.log"
    exit 1
fi

echo "[✓] Suricata aktif. Memantau alert real-time dari: $FAST_LOG"
echo "═══════════════════════════════════════"
echo ""

# Fungsi untuk dieksekusi saat Ctrl+C (SIGINT)
cleanup() {
    echo ""
    echo "==================================================="
    echo " [!] MENGHENTIKAN SURICATA & MENGAMBIL STATISTIK"
    echo "==================================================="
    
    # Hentikan tail
    kill "$TAIL_PID" 2>/dev/null
    
    # Beri sinyal ke Suricata untuk flush stats ke stats.log
    if kill -0 "$SURICATA_PID" 2>/dev/null; then
        sudo kill -SIGUSR1 "$SURICATA_PID"
        sleep 1
        sudo pkill -x suricata
    fi

    # Hitung jumlah Drop berdasarkan baris alert di fast.log
    DROPS=$(sudo grep -cv '^\s*$' "$FAST_LOG" 2>/dev/null || echo 0)
    
    # Total paket dari log statistik Suricata (baris decoder.pkts terakhir)
    TOTAL=$(sudo awk '/decoder.pkts/ {val=$NF} END {print val}' /var/log/suricata/stats.log 2>/dev/null)
    TOTAL=${TOTAL:-0}
    
    # Jika TOTAL kurang dari DROPS (karena delay flush log), samakan agar masuk akal
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

# Pasang trap
trap cleanup SIGINT SIGTERM

# Tampilkan alert secara real-time dan simpan PID-nya
tail -f "$FAST_LOG" &
TAIL_PID=$!

# Tunggu agar trap berfungsi (karena tail berjalan di background)
wait "$TAIL_PID"
