import os
import re
import sys

base_dir = "data-hasil_pengujian"
scenarios = ["01_suricata_only", "02_ml_only", "03_hybrid"]

# ============================================================================
# Ground Truth Logic:
#
# Kita membedakan request "attack" vs "normal" berdasarkan SUMBER pengiriman,
# bukan berdasarkan URL path. Mekanismenya:
#
#   1. Attack payloads dikirim oleh fungsi send_attack_traffic() di run_tests.sh
#      → Seluruhnya dikirim ke /vulnerabilities/sqli/?id=<PAYLOAD>&Submit=Submit
#      → Jumlah total yang DIKIRIM dicatat di attack_count.txt
#
#   2. Normal traffic dikirim oleh fungsi send_normal_traffic() dari wordlist
#      → Dikirim ke berbagai path DVWA
#      → Jumlah total yang DIKIRIM dicatat di normal_count.txt
#
#   3. dvwa_access.log mencatat request yang BERHASIL SAMPAI ke DVWA (lolos firewall)
#      → Docker log di-truncate sebelum tiap skenario, jadi isinya hanya dari run terbaru
#
# Confusion Matrix:
#   TP (Attack Blocked)  = attack_sent - attack_passed
#   FN (Attack Passed)   = attack_passed (sampai ke DVWA)
#   TN (Normal Passed)   = normal_passed (sampai ke DVWA)
#   FP (Normal Blocked)  = normal_sent - normal_passed
#
# Untuk membedakan attack vs normal di access log, kita gunakan penanda:
#   - Attack request selalu mengandung /vulnerabilities/sqli/ DAN parameter id=
#     dengan nilai NON-numerik (payload SQLi, bukan id=1 s/d id=9 yang normal)
#   - Normal request adalah sisanya
# ============================================================================

# Payload ID normal dari wordlist DVWA (angka murni 1-9, ini bukan serangan)
NORMAL_IDS = set(str(i) for i in range(1, 100))

def is_sqli_attack(url):
    """
    Tentukan apakah URL di access log adalah request serangan atau normal.
    Attack: /vulnerabilities/sqli/?id=<PAYLOAD_BERBAHAYA>&Submit=Submit
    Normal: /vulnerabilities/sqli/?id=<ANGKA>&Submit=Submit (browsing biasa)
            /vulnerabilities/sqli/source/low.php (melihat source code)
            /vulnerabilities/sqli/ (halaman utama tanpa parameter)
    """
    if "/vulnerabilities/sqli/" not in url:
        return False
    
    # Cek apakah ada parameter id=
    m = re.search(r'[?&]id=([^&]*)', url)
    if not m:
        # Tidak ada parameter id → ini browsing biasa (e.g., /source/low.php)
        return False
    
    id_value = m.group(1)
    
    # URL-decode untuk pengecekan
    try:
        from urllib.parse import unquote
        id_decoded = unquote(id_value)
    except ImportError:
        id_decoded = id_value
    
    # Jika id hanya berisi angka sederhana (1-99), ini normal browsing
    if id_decoded.strip() in NORMAL_IDS:
        return False
    
    # Selain itu, ini adalah payload serangan
    return True


def count_access_log(log_path):
    """Parse DVWA Docker access log dan hitung request yang lolos."""
    counts = {"attack_passed": 0, "normal_passed": 0}
    if not os.path.exists(log_path):
        return counts
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if 'HTTP/' not in line:
                continue
            m = re.search(r'"(?:GET|POST)\s+(\S+)\s+HTTP', line)
            if not m:
                continue
            url = m.group(1)
            if is_sqli_attack(url):
                counts["attack_passed"] += 1
            else:
                counts["normal_passed"] += 1
    return counts


def read_count_file(filepath):
    """Baca file yang berisi angka tunggal."""
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, 'r') as f:
            return int(f.read().strip())
    except (ValueError, IOError):
        return None


def main():
    # Jika dipanggil dengan argumen, hanya proses skenario yang disebutkan
    target_scenarios = scenarios
    if len(sys.argv) > 1:
        # Check if the exact scenario folder name was passed
        arg_scenario = sys.argv[1].strip().strip('/')
        if arg_scenario in scenarios:
            target_scenarios = [arg_scenario]
        else:
            # Fallback to substring match
            target_scenarios = [s for s in scenarios if any(arg in s for arg in sys.argv[1:])]
            if not target_scenarios:
                target_scenarios = scenarios
    
    print("Menganalisis hasil pengujian dan menghasilkan statistik...")
    
    for scenario in target_scenarios:
        scenario_dir = os.path.join(base_dir, scenario)
        if not os.path.exists(scenario_dir):
            continue
        
        stats_dir = os.path.join(scenario_dir, "stats")
        os.makedirs(stats_dir, exist_ok=True)
        
        # === Baca Ground Truth: berapa yang DIKIRIM ===
        attack_sent = read_count_file(os.path.join(scenario_dir, "user", "attack_count.txt"))
        normal_sent = read_count_file(os.path.join(scenario_dir, "user", "normal_count.txt"))
        
        if attack_sent is None or normal_sent is None:
            print(f"[SKIP] {scenario}: attack_count.txt atau normal_count.txt tidak ditemukan.")
            continue
        
        # === Hitung dari Access Log: berapa yang LOLOS ===
        access_log = os.path.join(scenario_dir, "target", "dvwa_access.log")
        passed = count_access_log(access_log)
        
        attack_passed = passed["attack_passed"]
        normal_passed = passed["normal_passed"]
        
        # === Hitung Confusion Matrix ===
        TP = attack_sent - attack_passed   # Attack berhasil diblokir
        FN = attack_passed                  # Attack lolos ke DVWA
        TN = normal_passed                  # Normal lolos ke DVWA (benar)
        FP = normal_sent - normal_passed   # Normal diblokir (salah)
        
        # Sanity check: pastikan tidak negatif
        TP = max(0, TP)
        FP = max(0, FP)
        
        # === Hitung Metrics ===
        total = TP + TN + FP + FN
        accuracy  = (TP + TN) / total if total > 0 else 0
        precision = TP / (TP + FP) if (TP + FP) > 0 else 0
        recall    = TP / (TP + FN) if (TP + FN) > 0 else 0  # TPR
        fpr       = FP / (FP + TN) if (FP + TN) > 0 else 0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        report = (
            f"=== STATISTIK {scenario.upper()} ===\n"
            f"\n--- INPUT ---\n"
            f"Attack Payloads Sent  : {attack_sent}\n"
            f"Normal Requests Sent  : {normal_sent}\n"
            f"Total Requests        : {attack_sent + normal_sent}\n"
            f"\n--- CONFUSION MATRIX ---\n"
            f"True Positives  (Attack Blocked) : {TP}\n"
            f"False Negatives (Attack Passed)  : {FN}\n"
            f"True Negatives  (Normal Passed)  : {TN}\n"
            f"False Positives (Normal Blocked)  : {FP}\n"
            f"\n--- METRICS ---\n"
            f"Accuracy  : {accuracy:.4f}\n"
            f"Precision : {precision:.4f}\n"
            f"Recall    : {recall:.4f}\n"
            f"F1-Score  : {f1:.4f}\n"
            f"FPR       : {fpr:.4f}\n"
        )
        
        with open(os.path.join(stats_dir, "metrics.txt"), "w") as f:
            f.write(report)
        
        print(report)


if __name__ == "__main__":
    main()
