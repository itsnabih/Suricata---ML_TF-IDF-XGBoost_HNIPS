#!/bin/bash
# ============================================================
#  firewall-scripts/run_ml.sh
#  Menjalankan ML Runner (Q3) dengan output inspeksi real-time.
#  Jalankan SETELAH setup_ml_only.sh atau setup_hybrid.sh.
# ============================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ML_SCRIPT="$PROJECT_DIR/model_ML_run.py"
QUEUE_NUM="3"

echo ""
echo "   NODE FIREWALL 2: ML RUNNER (XGBoost)   "
echo ""
echo " ML Runner akan menginspeksi traffic di NFQUEUE $QUEUE_NUM"
echo " Setiap payload yang terdeteksi akan ditampilkan real-time."
echo " Format: [KEPUTUSAN] Payload | Probabilitas Serangan: X.XX%"
echo " Tekan Ctrl+C untuk menghentikan."
echo ""
echo "--------------------------------------------------------"
echo ""

# Pastikan tidak ada ML Runner yang sudah berjalan
sudo pkill -f model_ML_run.py 2>/dev/null
sleep 1

# Jalankan ML Runner di foreground (--log-payloads untuk inspeksi real-time)
# --log-level DEBUG untuk output paling verbose
# --max-log-len 300 agar payload panjang tetap terbaca
cd "$PROJECT_DIR" && sudo python3 "$ML_SCRIPT" \
    --queue "$QUEUE_NUM" \
    --log-payloads \
    --log-level INFO \
    --max-log-len 300 \
    --report-every 50
