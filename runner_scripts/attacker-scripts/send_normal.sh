#!/bin/bash

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LOG_DIR="$SCRIPT_DIR/saved_logs/attacker"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/log-nomor 2_send_normal.txt"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "[LOG] Logging dimulai: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[LOG] File log: $LOG_FILE"

NORMAL_FILE="$PROJECT_DIR/dvwa_wordlist.txt"
TARGET_IP="172.17.0.2"
COOKIE="PHPSESSID=pgdrle5m5kd2rdvs9rbp8u6il6; security=low"
DELAY=0.3

if [ -n "$1" ]; then
    COOKIE="$1"
fi

TOTAL=$(grep -cv '^\s*$\|^#' "$NORMAL_FILE" 2>/dev/null || echo 0)

echo ""
echo "     NODE ATTACKER: SEND NORMAL TRAFFIC (Wordlist)    "
echo "  Target  : http://$TARGET_IP                          "
echo "  File    : $NORMAL_FILE"
echo "  Requests: $TOTAL                                    "
echo ""
echo "  Format output:"
echo "  -> Menampilkan URL yang dikunjungi"
echo "  -> HTTP Status Code respons"
echo "  (Semua request normal HARUS lolos -> HTTP 200/302)"
echo ""
echo "--------------------------------------------------------"

COUNT=0
FALSE_POS=0
SUCCESS=0

while IFS= read -r path; do
    [[ -z "$path" || "$path" == \#* ]] && continue

    COUNT=$((COUNT + 1))
    FULL_URL="http://$TARGET_IP${path}"

    HTTP_STATUS=$(curl -s -o /dev/null --max-time 2 \
        -w "%{http_code}" \
        "$FULL_URL" \
        -H "Cookie: $COOKIE")

    if [ "$HTTP_STATUS" = "000" ]; then
        LABEL="[DROP] DIBLOKIR (False Positive!) "
        FALSE_POS=$((FALSE_POS + 1))
    elif [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "302" ]; then
        LABEL="[PASS] OK -> HTTP $HTTP_STATUS"
        SUCCESS=$((SUCCESS + 1))
    else
        LABEL="[WARN] HTTP $HTTP_STATUS"
        SUCCESS=$((SUCCESS + 1))
    fi

    printf "[%3d/%d] %-55s %s\n" "$COUNT" "$TOTAL" "${path:0:55}" "$LABEL"

    sleep "$DELAY"
done < "$NORMAL_FILE"

echo ""
echo "--------------------------------------------------------"
echo "  RINGKASAN TRAFFIC NORMAL:"
echo "  Total Request Dikirim   : $COUNT"
echo "  Berhasil (True Negative): $SUCCESS"
echo "  Diblokir (False Positive): $FALSE_POS"
echo "--------------------------------------------------------"
echo ""
