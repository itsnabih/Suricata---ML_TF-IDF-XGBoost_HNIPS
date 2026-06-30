import os
import re
import json

base_dir = "data-hasil_pengujian"
scenarios = ["01_suricata_only", "02_ml_only", "03_hybrid"]

def is_attack(path):
    if "/vulnerabilities/sqli/" in path:
        return True
    return False

def extract_from_access_log(log_path):
    counts = {"attack": 0, "benign": 0}
    if not os.path.exists(log_path): return counts
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if 'HTTP/' not in line: continue
            m = re.search(r'\"(?:GET|POST)\s+(\S+)\s+HTTP', line)
            if not m: continue
            url = m.group(1)
            if is_attack(url): counts["attack"] += 1
            else: counts["benign"] += 1
    return counts

def main():
    print("Menganalisis hasil pengujian dan menghasilkan statistik...")
    for scenario in scenarios:
        scenario_dir = os.path.join(base_dir, scenario)
        if not os.path.exists(scenario_dir):
            continue
            
        stats_dir = os.path.join(scenario_dir, "stats")
        os.makedirs(stats_dir, exist_ok=True)
        
        # Karena kita ingin Confusion Matrix, FPR, TPR, kita butuh:
        # TP: Attack yang diblokir
        # FN: Attack yang lolos
        # TN: Benign yang lolos
        # FP: Benign yang diblokir
        
        # Kita gunakan dvwa_access.log sebagai sumber kebenaran (Ground Truth) untuk paket yang LOLOS.
        passed = extract_from_access_log(os.path.join(scenario_dir, "target", "dvwa_access.log"))
        FN = passed["attack"]
        TN = passed["benign"]
        
        # Untuk paket yang DIBLOKIR, karena keterbatasan log iptables/suricata dalam mengaitkan request HTTP dengan drop,
        # kita estimasi total request SQLMap yang seharusnya dikirim.
        # Atau lebih baik, kita parsing log Firewall (ml_stdout.log / suricata) untuk mendapatkan jumlah DROP yang eksplisit.
        
        TP = 0
        FP = 0
        
        ml_log = os.path.join(scenario_dir, "firewall", "ml_stdout.log")
        if os.path.exists(ml_log):
            with open(ml_log, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if " - DROP " in line:
                        m = re.search(r'path=(\S+)', line)
                        if m:
                            if is_attack(m.group(1)): TP += 1
                            else: FP += 1

        suricata_log = os.path.join(scenario_dir, "firewall", "suricata_eve.json")
        if os.path.exists(suricata_log):
            flows_blocked = set()
            flows_url = {}
            with open(suricata_log, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        fid = event.get("flow_id")
                        if event.get("event_type") == "http":
                            flows_url[fid] = event["http"]["url"]
                        elif event.get("event_type") == "alert":
                            if event.get("alert", {}).get("action") == "blocked":
                                flows_blocked.add(fid)
                    except: pass
            for fid in flows_blocked:
                if fid in flows_url:
                    if is_attack(flows_url[fid]): TP += 1
                    else: FP += 1

        # Calculate metrics
        total = TP + TN + FP + FN
        accuracy = (TP + TN) / total if total > 0 else 0
        fpr = FP / (FP + TN) if (FP + TN) > 0 else 0
        tpr = TP / (TP + FN) if (TP + FN) > 0 else 0 # Recall
        precision = TP / (TP + FP) if (TP + FP) > 0 else 0
        
        report = (
            f"=== STATISTIK {scenario.upper()} ===\n"
            f"Total Requests Processed: {total}\n"
            f"\n--- CONFUSION MATRIX ---\n"
            f"True Positives (Attack Blocked) : {TP}\n"
            f"False Negatives (Attack Passed) : {FN}\n"
            f"True Negatives (Benign Passed)  : {TN}\n"
            f"False Positives (Benign Blocked): {FP}\n"
            f"\n--- METRICS ---\n"
            f"Accuracy : {accuracy:.4f}\n"
            f"Precision: {precision:.4f}\n"
            f"Recall (TPR): {tpr:.4f}\n"
            f"False Positive Rate (FPR): {fpr:.4f}\n"
        )
        
        with open(os.path.join(stats_dir, "metrics.txt"), "w") as f:
            f.write(report)
            
        print(report)

if __name__ == "__main__":
    main()
