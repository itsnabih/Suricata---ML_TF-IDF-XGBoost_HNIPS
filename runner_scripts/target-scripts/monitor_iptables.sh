#!/bin/bash
# ============================================================
#  target-scripts/monitor_iptables.sh
#  Memantau statistik packet counter pada MANGLE dan FILTER
#  secara real-time menggunakan 'watch'.
#  Berguna untuk membuktikan berapa paket yang di-NFQUEUE.
# ============================================================

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

watch -n "$INTERVAL" '
echo "--------------------------------------------------------"
echo "  IPTABLES PACKET COUNTER — $(date "+%H:%M:%S")"
echo "--------------------------------------------------------"
echo ""
echo "  ── TABEL MANGLE (Garda 1: Suricata) ──────────────"
sudo iptables -t mangle -L -v -n --line-numbers 2>/dev/null | grep -E "NFQUEUE|pkts|bytes|Chain" || echo "  (Tidak ada rule MANGLE aktif)"
echo ""
echo "  ── TABEL FILTER (Garda 2: ML Runner) ─────────────"
sudo iptables -t filter -L -v -n --line-numbers 2>/dev/null | grep -E "NFQUEUE|pkts|bytes|Chain" || echo "  (Tidak ada rule FILTER aktif)"
echo ""
echo "  Tip: Kolom pertama = paket (#pkts), kedua = bytes"
'
