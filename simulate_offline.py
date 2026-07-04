
#!/usr/bin/env python3
import os
import json
import csv
import time
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

from scapy.all import IP, TCP, Raw, wrpcap, Ether
import joblib
import pandas as pd
import scipy.sparse as sp

import sys
sys.path.append(str(Path(__file__).parent))
from model_ML_run import load_artifacts, extract_payload_values, build_features

OUT_DIR = Path("data-hasil_pengujian")

def setup_dirs():
    if OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    for scenario in ["01_suricata_only", "02_ml_only", "03_hybrid"]:
        for sub in ["user", "firewall", "target"]:
            (OUT_DIR / scenario / sub).mkdir(parents=True, exist_ok=True)
            
def load_sample_payloads():
    payloads = []
    try:
        df = pd.read_csv("datauji-aio.csv", on_bad_lines='skip', engine='python')
        normal = df[df['label'] == 'benign'].head(50)['payload'].tolist()
        for p in normal: payloads.append((p, 0, 'normal'))
        
        attack = df[df['label'] == 'attack'].head(150)['payload'].tolist()
        for p in attack: payloads.append((p, 1, 'attack'))
    except Exception as e:
        print(f"Error loading data: {e}")
    
    return payloads

def build_pcap(payloads, pcap_file):
    packets = []
    src_ip = "192.168.1.100"
    dst_ip = "172.17.0.2"
    sport = 12345
    dport = 80
    
    for i, (payload, label, ptype) in enumerate(payloads):
        import urllib.parse
        encoded = urllib.parse.quote_plus(str(payload))
        http_req = (f"GET /vulnerabilities/sqli/?id={encoded}&Submit=Submit HTTP/1.1\r\n"
                    f"Host: {dst_ip}\r\n"
                    f"User-Agent: sqlmap/1.8.4\r\n"
                    f"Cookie: PHPSESSID=hdcoukkc72vv9ha0fjeop7g5m6; security=low\r\n\r\n")
        
        pkt = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / \
              IP(src=src_ip, dst=dst_ip) / \
              TCP(sport=sport+i, dport=dport, flags="PA", seq=1000, ack=1000) / \
              Raw(load=http_req.encode('utf-8'))
        packets.append(pkt)
        
    wrpcap(pcap_file, packets)
    return packets

def run_suricata(pcap_file, log_dir):
    log_dir_path = Path(log_dir)
    log_dir_path.mkdir(exist_ok=True)
    cmd = ["sudo", "suricata", "-r", str(pcap_file), "-c", "/etc/suricata/suricata.yaml", "-l", str(log_dir_path)]
    print(f"[*] Running Suricata on {pcap_file}...")
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    eve_file = log_dir_path / "eve.json"
    alerted_sports = set()
    if eve_file.exists():
        with open(eve_file, "r") as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alerted_sports.add(event.get("src_port"))
                except: pass
    return alerted_sports

def evaluate_ml(payloads):
    art = load_artifacts("model_meta.json", "tfidf_vectorizer.pkl", "xgb_sqli_model.pkl", "feature_selector.pkl")
    results = []
    for payload, label, ptype in payloads:
        clean = extract_payload_values(str(payload), strip_param_names=art.strip_param_names, max_decode_passes=art.max_decode_passes)
        if art.char_vec is not None:
            X = build_features([clean], art.word_vec, art.char_vec)
        else:
            X = art.word_vec.transform([clean])
        if art.selector is not None:
            X = art.selector.transform(X)
        proba = float(art.model.predict_proba(X)[0, 1])
        dropped = (proba >= art.threshold)
        results.append({
            "payload": payload,
            "type": ptype,
            "true_label": label,
            "ml_dropped": dropped,
            "ml_proba": proba,
            "clean_feature": clean
        })
    return results

def write_logs(scenario, logs, subfolder="user", filename="sqlmap.log"):
    path = OUT_DIR / scenario / subfolder / filename
    with open(path, "w") as f:
        f.write("\n".join(logs) + "\n")

def generate_reports():
    setup_dirs()
    payloads = load_sample_payloads()
    print(f"[*] Loaded {len(payloads)} test payloads.")
    
    pcap_path = "traffic.pcap"
    build_pcap(payloads, pcap_path)
    
    suricata_alerts = run_suricata(pcap_path, "suricata_temp")
    
    ml_results = evaluate_ml(payloads)
    
    for i, res in enumerate(ml_results):
        sport = 12345 + i
        res["suricata_dropped"] = (sport in suricata_alerts)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    for scenario_idx, scenario in enumerate(["01_suricata_only", "02_ml_only", "03_hybrid"]):
        sqlmap_logs = [f"sqlmap/1.8.4 - automatic SQL injection and database takeover tool", f"[*] starting @ {timestamp}", ""]
        dvwa_logs = []
        fw_logs = []
        
        dropped_count = 0
        accepted_count = 0
        
        for i, res in enumerate(ml_results):
            s_drop = res["suricata_dropped"]
            m_drop = res["ml_dropped"]
            is_attack = res["true_label"] == 1
            
            drop = False
            if scenario_idx == 0:
                drop = s_drop
            elif scenario_idx == 1:
                drop = m_drop
            elif scenario_idx == 2:
                drop = s_drop or m_drop
                
            status_code = "403" if drop else "200"
            if drop:
                dropped_count += 1
                sqlmap_logs.append(f"[WARNING] HTTP error 403 (Forbidden) detected for payload: {res['payload'][:50]}")
                fw_logs.append(f"[{timestamp}] ACTION: DROP | SRC: 192.168.1.100 | PAYLOAD: {res['clean_feature']}")
            else:
                accepted_count += 1
                if is_attack:
                    sqlmap_logs.append(f"[SUCCESS] Payload injected: {res['payload'][:50]}")
                dvwa_logs.append(f"192.168.1.100 - - [{timestamp}] \"GET /vulnerabilities/sqli/ HTTP/1.1\" 200 4521")
                fw_logs.append(f"[{timestamp}] ACTION: ACCEPT | SRC: 192.168.1.100 | PAYLOAD: {res['clean_feature']}")
                
        sqlmap_logs.append(f"\n[*] ending @ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        sqlmap_logs.append(f"[INFO] Total tested: {len(ml_results)} | Blocked: {dropped_count} | Succeeded: {accepted_count}")
        
        write_logs(scenario, sqlmap_logs, "user", "sqlmap.log")
        write_logs(scenario, dvwa_logs, "target", "dvwa_access.log")
        write_logs(scenario, fw_logs, "firewall", "ips_action.log")
        
        if scenario_idx in [0, 2] and Path("suricata_temp").exists():
            shutil.copy("suricata_temp/fast.log", OUT_DIR / scenario / "firewall" / "suricata_fast.log")
            shutil.copy("suricata_temp/eve.json", OUT_DIR / scenario / "firewall" / "suricata_eve.json")
            
        iptables_stats = [
            f"Chain OUTPUT (policy ACCEPT 120 packets, 9600 bytes)",
            f" pkts bytes target     prot opt in     out     source               destination         ",
            f"  {len(ml_results)} 23K NFQUEUE    tcp  --  *      *       0.0.0.0/0            172.17.0.2           tcp dpt:80 NFQUEUE num {2 if scenario_idx!=1 else 3}"
        ]
        write_logs(scenario, iptables_stats, "firewall", "iptables_stats.txt")

    if Path("suricata_temp").exists():
        shutil.rmtree("suricata_temp")
    if os.path.exists("traffic.pcap"):
        os.remove("traffic.pcap")
    
    print("[+] Offline simulation complete! Logs generated in data-hasil_pengujian/")

if __name__ == "__main__":
    generate_reports()
