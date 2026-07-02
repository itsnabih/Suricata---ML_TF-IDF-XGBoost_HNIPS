#!/bin/bash
# ============================================================
#  target-scripts/monitor_web_log.sh
#  Memantau akses log DVWA (web server) secara real-time.
#  Gunakan untuk membuktikan apakah serangan masuk ke server.
# ============================================================

DVWA_CONTAINER="dvwa"

echo ""
echo "     NODE TARGET: WEB SERVER ACCESS LOG (DVWA)        "
echo ""
echo "  Memantau log akses Apache/Nginx di dalam container DVWA."
echo "  Jika IPS bekerja: request berbahaya TIDAK akan muncul di sini."
echo "  Jika muncul: paket berhasil menembus pertahanan (lolos)."
echo ""
echo "  Format log: [IP] - [user] [timestamp] \"METHOD /path\" [status] [bytes]"
echo ""
echo "  [OK] HTTP 200: Request lolos ke web server"
echo "  [FAIL] Tidak muncul: Paket di-DROP oleh IPS (berhasil diblokir)"
echo ""
echo "--------------------------------------------------------"
echo ""

# Periksa apakah container berjalan
if ! sudo docker ps --format '{{.Names}}' | grep -q "^${DVWA_CONTAINER}$"; then
    echo "[WARN] ERROR: Container '$DVWA_CONTAINER' tidak berjalan!"
    echo "    Jalankan: sudo docker start $DVWA_CONTAINER"
    exit 1
fi

echo "[INFO] Menampilkan log akses container '$DVWA_CONTAINER' secara real-time..."
echo ""

# Follow log container secara real-time
sudo docker logs -f --tail=20 "$DVWA_CONTAINER"
