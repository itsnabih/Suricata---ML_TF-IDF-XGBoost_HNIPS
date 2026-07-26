#!/bin/bash

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LOG_DIR="$SCRIPT_DIR/saved_logs/firewall"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/log-nomor 5_run_ml.txt"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "[LOG] Logging dimulai: $(date '+%Y-%m-%d %H:%M:%S')"
echo "[LOG] File log: $LOG_FILE"

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

sudo pkill -f model_ML_run.py 2>/dev/null
sleep 1

cd "$PROJECT_DIR" && sudo python3 "$ML_SCRIPT" \
    --queue "$QUEUE_NUM" \
    --log-payloads \
    --log-level INFO \
    --max-log-len 300 \
    --report-every 50
