#!/bin/bash

# Configuration
TARGET="http://172.17.0.2/vulnerabilities/sqli/?id=1&Submit=Submit"
COOKIE="PHPSESSID=vgaqqh5gc08093scgsg7lkmi20; security=low"
OUT_DIR="data-hasil_pengujian"
DVWA_CONTAINER="dvwa"
SURICATA_CONF="/etc/suricata/suricata.yaml"
ML_SCRIPT="model_ML_run.py"

# === Level 1 Flags: Scenario Selection ===
RUN_SURICATA=false
RUN_ML=false
RUN_HYBRID=false

# === Level 2-3 Flags: Custom Payload Sources ===
ATTACK_FILE="sqli_payloads.txt"          # --attack <file> : gunakan payload file, bukan SQLMap
NORMAL_WORDLIST="dvwa_wordlist.txt"  # --wordlist <file> : override wordlist normal

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <scenario> [options]"
    echo ""
    echo "Level 1 — Scenario Selection (wajib, pilih minimal 1):"
    echo "  --suricata    Jalankan Skenario 1: Suricata Only"
    echo "  --ML          Jalankan Skenario 2: ML Only"
    echo "  --hybrid      Jalankan Skenario 3: Hybrid (Suricata + ML)"
    echo "  --all         Jalankan semua skenario"
    echo ""
    echo "Level 2-3 — Custom Payload (opsional):"
    echo "  --attack <file>    Gunakan file payload SQLi (menggantikan SQLMap)"
    echo "                     Setiap baris dikirim sebagai ?id=<PAYLOAD>&Submit=Submit"
    echo "  --wordlist <file>  Override wordlist traffic normal (default: dvwa_wordlist.txt)"
    exit 1
fi

# Parse arguments (support flags with values)
while [ "$#" -gt 0 ]; do
    case $1 in
        --suricata) RUN_SURICATA=true ;;
        --ML)       RUN_ML=true ;;
        --hybrid)   RUN_HYBRID=true ;;
        --all)
            RUN_SURICATA=true
            RUN_ML=true
            RUN_HYBRID=true
            ;;
        --attack)
            shift
            if [ -z "$1" ] || [[ "$1" == --* ]]; then
                echo "Error: --attack requires a file path argument"
                exit 1
            fi
            ATTACK_FILE="$1"
            if [ ! -f "$ATTACK_FILE" ]; then
                echo "Error: Attack file '$ATTACK_FILE' not found"
                exit 1
            fi
            ;;
        --wordlist)
            shift
            if [ -z "$1" ] || [[ "$1" == --* ]]; then
                echo "Error: --wordlist requires a file path argument"
                exit 1
            fi
            NORMAL_WORDLIST="$1"
            if [ ! -f "$NORMAL_WORDLIST" ]; then
                echo "Error: Wordlist file '$NORMAL_WORDLIST' not found"
                exit 1
            fi
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
    shift
done

# Validasi: minimal satu skenario harus dipilih
if [ "$RUN_SURICATA" = false ] && [ "$RUN_ML" = false ] && [ "$RUN_HYBRID" = false ]; then
    echo "Error: Pilih minimal satu skenario (--suricata, --ML, --hybrid, --all)"
    exit 1
fi

# Print konfigurasi
echo "========================================="
echo " KONFIGURASI PENGUJIAN"
echo "========================================="
if [ -n "$ATTACK_FILE" ]; then
    ATTACK_COUNT=$(grep -cv '^\s*$\|^#' "$ATTACK_FILE")
    echo " Attack Mode : Custom payload ($ATTACK_FILE, $ATTACK_COUNT payloads)"
else
    echo " Attack Mode : SQLMap (automated)"
fi
NORMAL_COUNT=$(grep -cv '^\s*$\|^#' "$NORMAL_WORDLIST")
echo " Normal Mode : Wordlist ($NORMAL_WORDLIST, $NORMAL_COUNT URLs)"
echo " Scenarios   : $([ "$RUN_SURICATA" = true ] && echo "Suricata ") $([ "$RUN_ML" = true ] && echo "ML ") $([ "$RUN_HYBRID" = true ] && echo "Hybrid")"
echo "========================================="

mkdir -p "$OUT_DIR"/{01_suricata_only,02_ml_only,03_hybrid}/{user,firewall,target}
sudo chown -R "$(id -u):$(id -g)" "$OUT_DIR"

function cleanup() {
    sudo iptables -t filter -F
    sudo iptables -t mangle -F
    sudo pkill -x suricata
    sudo pkill -f model_ML_run.py
    # Bersihkan log Docker dengan cara yang aman (Stop -> Truncate -> Start) agar file JSON tidak korup
    sudo docker stop $DVWA_CONTAINER
    sudo sh -c "truncate -s 0 /var/lib/docker/containers/\$(sudo docker inspect -f '{{.Id}}' $DVWA_CONTAINER)/*-json.log"
    sudo docker start $DVWA_CONTAINER
    sleep 7
}

function fetch_logs() {
    local scenario_dir=$1
    echo "[*] Fetching logs to $scenario_dir..."

    # Target logs
    sudo docker logs "$DVWA_CONTAINER" > "$scenario_dir/target/dvwa_access.log" 2>&1

    # Iptables stats
    sudo iptables -L -v -n > "$scenario_dir/firewall/iptables_stats.txt"

    # Suricata logs
    if [ -f /var/log/suricata/fast.log ]; then
        sudo cp /var/log/suricata/fast.log "$scenario_dir/firewall/suricata_fast.log"
    fi
    if [ -f /var/log/suricata/eve.json ]; then
        sudo cp /var/log/suricata/eve.json "$scenario_dir/firewall/suricata_eve.json"
    fi
}

function clear_logs() {
    sudo truncate -s 0 /var/log/suricata/fast.log 2>/dev/null || true
    sudo truncate -s 0 /var/log/suricata/eve.json 2>/dev/null || true
    sudo truncate -s 0 /var/log/suricata/stats.log 2>/dev/null || true
}

function purge_scenario() {
    local scenario_dir=$1
    echo "[*] Purging old data in $scenario_dir..."
    rm -rf "$scenario_dir"/{user,firewall,target,stats}
    mkdir -p "$scenario_dir"/{user,firewall,target,stats}
}

# === Fungsi pengiriman traffic ===
# Mengirim serangan: SQLMap ATAU custom payload file
function send_attack_traffic() {
    local log_dir=$1

    if [ -n "$ATTACK_FILE" ]; then
        echo "[*] Sending attack payloads from $ATTACK_FILE..."
        local count=0
        local total=$(grep -cv '^\s*$\|^#' "$ATTACK_FILE")
        while IFS= read -r payload; do
            [[ -z "$payload" || "$payload" == \#* ]] && continue
            count=$((count + 1))
            # Kirim payload sebagai parameter id ke halaman SQLi DVWA
            # --max-time 1: timeout 1 detik (sangat ideal untuk local container)
            # --data-urlencode: encode payload agar karakter spesial aman ditransmisikan
            curl -s --max-time 1 \
                -G "http://172.17.0.2/vulnerabilities/sqli/" \
                --data-urlencode "id=$payload" \
                --data-urlencode "Submit=Submit" \
                -H "Cookie: $COOKIE" \
                > /dev/null 2>&1
            # Progress indicator setiap 50 payload
            if (( count % 50 == 0 )); then
                echo "    [$count/$total] payloads sent..."
            fi
        done < "$ATTACK_FILE"
        echo "    [DONE] $count attack payloads sent."
        echo "$count" > "$log_dir/user/attack_count.txt"
    else
        echo "[*] Running SQLMap..."
        sqlmap -u "$TARGET" --cookie="$COOKIE" -p id --random-agent --batch --level=2 --risk=2 > "$log_dir/user/sqlmap.log" 2>&1
    fi
}

# Mengirim traffic normal dari wordlist
function send_normal_traffic() {
    local log_dir=$1
    echo "[*] Sending normal traffic from $NORMAL_WORDLIST..."
    local count=0
    while IFS= read -r path; do
        [[ -z "$path" || "$path" == \#* ]] && continue
        count=$((count + 1))
        curl -s --max-time 1 "http://172.17.0.2${path}" -H "Cookie: $COOKIE" > /dev/null 2>&1
    done < "$NORMAL_WORDLIST"
    echo "    [DONE] $count normal requests sent."
    echo "$count" > "$log_dir/user/normal_count.txt"
}

# ===========================================================================
#  SCENARIO 1: SURICATA ONLY
# ===========================================================================
if [ "$RUN_SURICATA" = true ]; then
echo "========================================="
echo " SCENARIO 1: SURICATA ONLY"
echo "========================================="
cleanup
clear_logs
purge_scenario "$OUT_DIR/01_suricata_only"
# Disable route-queue in suricata.yaml
sudo sed -i 's/^ *route-queue: 3/#  route-queue: 3/' "$SURICATA_CONF"

sudo iptables -I OUTPUT -p tcp -d 172.17.0.2 --dport 80 -j NFQUEUE --queue-num 2
sudo iptables -I INPUT -p tcp -s 172.17.0.2 --sport 80 -j NFQUEUE --queue-num 2

sudo suricata -c "$SURICATA_CONF" -q 2 > "$OUT_DIR/01_suricata_only/firewall/suricata_stdout.log" 2>&1 &
SURICATA_PID=$!
sleep 5

send_attack_traffic "$OUT_DIR/01_suricata_only"
send_normal_traffic "$OUT_DIR/01_suricata_only"

fetch_logs "$OUT_DIR/01_suricata_only"
cleanup
python3 calculate_stats.py 01_suricata_only
fi

# ===========================================================================
#  SCENARIO 2: ML ONLY
# ===========================================================================
if [ "$RUN_ML" = true ]; then
echo "========================================="
echo " SCENARIO 2: ML ONLY"
echo "========================================="
cleanup
clear_logs
purge_scenario "$OUT_DIR/02_ml_only"

sudo iptables -I OUTPUT -p tcp -d 172.17.0.2 --dport 80 -j NFQUEUE --queue-num 3
sudo iptables -I INPUT -p tcp -s 172.17.0.2 --sport 80 -j NFQUEUE --queue-num 3

sudo python3 "$ML_SCRIPT" --queue 3 --log-payloads --csv-log "$OUT_DIR/02_ml_only/firewall/ml_inspection.csv" > "$OUT_DIR/02_ml_only/firewall/ml_stdout.log" 2>&1 &
ML_PID=$!
sleep 5

send_attack_traffic "$OUT_DIR/02_ml_only"
send_normal_traffic "$OUT_DIR/02_ml_only"

fetch_logs "$OUT_DIR/02_ml_only"
cleanup
python3 calculate_stats.py 02_ml_only
fi

# ===========================================================================
#  SCENARIO 3: HYBRID (Suricata + ML)
# ===========================================================================
if [ "$RUN_HYBRID" = true ]; then
echo "========================================="
echo " SCENARIO 3: HYBRID (Suricata + ML)"
echo "========================================="
cleanup
clear_logs
purge_scenario "$OUT_DIR/03_hybrid"

# Enable route-queue
sudo sed -i 's/#  route-queue: 3/  route-queue: 3/' "$SURICATA_CONF"

# Konfigurasi Cascading Iptables untuk Hybrid (Solusi Pasti):
# Di Linux, jika NFQUEUE mengembalikan verdict ACCEPT, paket akan BERHENTI dievaluasi di tabel yang sama.
# Agar paket bisa dievaluasi oleh DUA NFQUEUE yang berbeda (Suricata lalu ML), kita harus meletakkannya di tabel (table) yang berbeda.
# Urutan traversing iptables: MANGLE -> FILTER.
# Oleh karena itu, kita tempatkan Suricata di tabel 'mangle' dan ML di tabel 'filter'.

# 1. Tabel MANGLE untuk Suricata (Queue 2) - Dijalankan PERTAMA
sudo iptables -t mangle -I OUTPUT -p tcp -d 172.17.0.2 --dport 80 -j NFQUEUE --queue-num 2
sudo iptables -t mangle -I INPUT -p tcp -s 172.17.0.2 --sport 80 -j NFQUEUE --queue-num 2

# 2. Tabel FILTER untuk ML (Queue 3) - Dijalankan KEDUA (Jika lolos dari Mangle)
sudo iptables -t filter -I OUTPUT -p tcp -d 172.17.0.2 --dport 80 -j NFQUEUE --queue-num 3
sudo iptables -t filter -I INPUT -p tcp -s 172.17.0.2 --sport 80 -j NFQUEUE --queue-num 3

sudo suricata -c "$SURICATA_CONF" -q 2 > "$OUT_DIR/03_hybrid/firewall/suricata_stdout.log" 2>&1 &
sudo python3 "$ML_SCRIPT" --queue 3 --log-payloads --csv-log "$OUT_DIR/03_hybrid/firewall/ml_inspection.csv" > "$OUT_DIR/03_hybrid/firewall/ml_stdout.log" 2>&1 &
sleep 5

send_attack_traffic "$OUT_DIR/03_hybrid"
send_normal_traffic "$OUT_DIR/03_hybrid"

fetch_logs "$OUT_DIR/03_hybrid"
cleanup
python3 calculate_stats.py 03_hybrid
fi

echo "[+] All scenarios completed!"
