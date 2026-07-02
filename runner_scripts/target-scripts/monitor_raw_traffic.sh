#!/bin/bash
# ============================================================
#  target-scripts/monitor_raw_traffic.sh
#  Menangkap dan menampilkan raw HTTP traffic secara real-time
#  menggunakan tcpdump pada interface docker (port 80).
#  Berguna untuk melihat payload mentah yang melintas di jaringan.
# ============================================================

TARGET_IP="172.17.0.2"
TARGET_PORT="80"
INTERFACE="any"  # Ganti ke 'docker0' jika ingin spesifik bridge Docker

echo ""
echo "     NODE TARGET: RAW TRAFFIC INSPECTOR (tcpdump)     "
echo ""
echo "  Menampilkan raw HTTP request/response yang melintas."
echo "  Interface : $INTERFACE"
echo "  Filter    : host $TARGET_IP and port $TARGET_PORT"
echo ""
echo "  Cara baca output tcpdump:"
echo "  Baris '.' = data ASCII dari payload HTTP"
echo "  Cari baris 'GET /vulnerabilities/sqli/?id=...' untuk payload SQLi"
echo ""
echo "  Tekan Ctrl+C untuk menghentikan."
echo "--------------------------------------------------------"
echo ""

# Pilihan mode inspeksi
echo "Pilih mode inspeksi:"
echo "  [1] HTTP Request Headers + URL saja (ringkas)"
echo "  [2] Full Raw Payload ASCII (detail, verbose)"
echo ""
read -rp "Masukkan pilihan [1/2, default=1]: " MODE
MODE="${MODE:-1}"

echo ""
echo "[INFO] Memulai tcpdump..."
echo ""

if [ "$MODE" = "2" ]; then
    # Mode verbose: tampilkan full ASCII payload (-A)
    sudo tcpdump -i "$INTERFACE" \
        "host $TARGET_IP and port $TARGET_PORT" \
        -A -n -l 2>/dev/null | grep --line-buffered -v "^$" | \
        grep --line-buffered -v "^E\." | \
        while IFS= read -r line; do
            # Highlight baris yang mengandung SQLi keywords
            if echo "$line" | grep -qiE "(select|union|insert|drop|--\+|%27|0x|sleep|benchmark|and\s+1=1)"; then
                echo -e "\e[1;31m[ SQLi?] $line\e[0m"
            elif echo "$line" | grep -qiE "(GET|POST|HTTP|Host:|Cookie:)"; then
                echo -e "\e[1;33m[HTTP]   $line\e[0m"
            else
                echo "         $line"
            fi
        done
else
    # Mode ringkas: hanya tampilkan baris HTTP method dan URL
    sudo tcpdump -i "$INTERFACE" \
        "host $TARGET_IP and port $TARGET_PORT" \
        -A -n -l 2>/dev/null | grep --line-buffered -E "^(GET|POST|PUT|DELETE|HTTP)" | \
        while IFS= read -r line; do
            if echo "$line" | grep -qiE "(select|union|insert|drop|--\+|%27|0x|sleep|benchmark|and\s+1=1)"; then
                echo -e "\e[1;31m[$(date '+%H:%M:%S')]  SQLi DETECTED: $line\e[0m"
            else
                echo -e "\e[0;32m[$(date '+%H:%M:%S')] NORMAL: $line\e[0m"
            fi
        done
fi
