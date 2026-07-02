# Panduan Pelaksanaan Pengujian Manual — Hybrid IPS
### Suricata + ML (TF-IDF XGBoost) — Inline NFQUEUE

---

## Prasyarat

Sebelum memulai, pastikan kondisi berikut terpenuhi:

| Komponen | Cara Verifikasi |
|----------|-----------------|
| Docker DVWA berjalan | `sudo docker ps \| grep dvwa` |
| IP DVWA = `172.17.0.2` | `sudo docker inspect dvwa \| grep IPAddress` |
| Suricata terinstal | `suricata --version` |
| NFQUEUE tersedia | `sudo modprobe xt_NFQUEUE && echo OK` |
| Model ML tersedia | `ls xgb_sqli_model.pkl tfidf_vectorizer.pkl` |
| Cookie DVWA valid | Login ke `http://172.17.0.2/login.php`, copy cookie |

> [!IMPORTANT]
> Cookie DVWA `PHPSESSID` memiliki masa expired. Jika pengujian gagal mendapat respons, login ulang ke DVWA dan perbarui variabel `COOKIE` di dalam script `attacker-scripts/send_attack.sh` dan `send_normal.sh`.

---

## Topologi Terminal (4 Node)

Buka **4 tab terminal secara bersamaan** dengan peran masing-masing:

```
┌─────────────────────┐   ┌─────────────────────┐
│   TERMINAL 1        │   │   TERMINAL 2        │
│   Firewall: Suricata│   │   Firewall: ML      │
│   (Node Suricata)   │   │   (Node ML Runner)  │
└─────────────────────┘   └─────────────────────┘

┌─────────────────────┐   ┌─────────────────────┐
│   TERMINAL 3        │   │   TERMINAL 4        │
│   Attacker: curl    │   │   Target: Inspector  │
│   (Node Penyerang)  │   │   (Node Server)     │
└─────────────────────┘   └─────────────────────┘
```

> [!NOTE]
> Semua perintah dijalankan dari **direktori root proyek** (`Suricata---ML_TF-IDF-XGBoost_HNIPS/`), bukan dari dalam folder `runner_scripts/`.

---

## 🔁 Langkah Awal (WAJIB sebelum SETIAP skenario)

Jalankan kedua perintah ini **di Terminal mana saja** setiap kali hendak berpindah skenario:

**Langkah 1 — Bersihkan proses & iptables lama:**
```bash
./runner_scripts/operation/cleanup.sh
```

**Langkah 2 — Kosongkan semua log:**
```bash
./runner_scripts/operation/reset_logs.sh
```

> [!WARNING]
> `reset_logs.sh` akan me-restart container DVWA untuk membersihkan log-nya. Tunggu hingga selesai (~7 detik) sebelum melanjutkan ke langkah setup skenario.

---

## Skenario 1: Suricata Only (Signature-Based)

**Arsitektur:** `Attacker -> iptables FILTER -> NFQUEUE 2 -> Suricata -> DROP/ACCEPT -> DVWA`

---

### Terminal 1 — Setup & Jalankan Suricata

```bash
# Langkah 1: Atur IPTables mengarah ke Suricata (Queue 2)
./runner_scripts/firewall-scripts/setup_suricata_only.sh

# Langkah 2: Jalankan Suricata & pantau alert real-time
./runner_scripts/firewall-scripts/run_suricata.sh
```

> Biarkan terminal ini berjalan. Alert SQLi akan muncul otomatis saat serangan dikirim.

---

### Terminal 4 — Inspeksi Target (pilih salah satu atau buka sub-tab)

```bash
# Opsi A: Pantau akses log web server DVWA
./runner_scripts/target-scripts/monitor_web_log.sh

# Opsi B: Pantau packet counter iptables real-time
./runner_scripts/target-scripts/monitor_iptables.sh

# Opsi C: Pantau raw HTTP payload via tcpdump
./runner_scripts/target-scripts/monitor_raw_traffic.sh
```

---

### Terminal 3 — Kirim Serangan & Traffic Normal

```bash
# Kirim serangan SQLi dari sqli_payloads.txt
./runner_scripts/attacker-scripts/send_attack.sh

# (Setelah selesai) Kirim traffic normal untuk uji False Positive
./runner_scripts/attacker-scripts/send_normal.sh
```

---

### Hasil yang Diharapkan (Skenario 1)

| Node | Yang Terlihat |
|------|---------------|
| **Terminal 1 (Suricata)** | Baris alert SQLi bermunculan untuk setiap payload yang cocok dengan rule |
| **Terminal 3 (Attacker)** | Status `[DROP] BLOCKED/DROPPED` untuk payload berbahaya, `[PASS] LOLOS` untuk traffic normal |
| **Terminal 4 (Target)** | Request berbahaya **TIDAK MUNCUL** di log DVWA (sudah di-DROP sebelum sampai server) |

---

---

## Skenario 2: ML Only (Anomaly-Based)

**Arsitektur:** `Attacker -> iptables FILTER -> NFQUEUE 3 -> ML XGBoost -> DROP/ACCEPT -> DVWA`

---

### Terminal 1 — Jalankan Cleanup (Terminal mana saja)

```bash
./runner_scripts/operation/cleanup.sh
./runner_scripts/operation/reset_logs.sh
```

### Terminal 2 — Setup & Jalankan ML Runner

```bash
# Langkah 1: Atur IPTables mengarah ke ML Runner (Queue 3)
./runner_scripts/firewall-scripts/setup_ml_only.sh

# Langkah 2: Jalankan ML Runner dengan inspeksi real-time per payload
./runner_scripts/firewall-scripts/run_ml.sh
```

> Setiap HTTP request yang ditangkap akan dicetak ke layar:
> format: `[DROP/ACCEPT] payload | prob: X.XXX`

---

### Terminal 4 — Inspeksi Target

```bash
# Pantau packet counter (kolom 'pkts' di FILTER naik seiring request)
./runner_scripts/target-scripts/monitor_iptables.sh
```

---

### Terminal 3 — Kirim Traffic

```bash
./runner_scripts/attacker-scripts/send_attack.sh
./runner_scripts/attacker-scripts/send_normal.sh
```

---

### Hasil yang Diharapkan (Skenario 2)

| Node | Yang Terlihat |
|------|---------------|
| **Terminal 2 (ML Runner)** | Output per-request: payload diekstrak, probabilitas dihitung, keputusan DROP/ACCEPT |
| **Terminal 3 (Attacker)** | `[DROP] BLOCKED` untuk payload dengan probabilitas ≥ threshold |
| **Terminal 4 (IPTables)** | Kolom `pkts` di tabel **FILTER** terus naik. Kolom MANGLE tetap 0 (tidak aktif) |

---

---

## Skenario 3: Hybrid (Suricata + ML Cascading)

**Arsitektur:**
```
Attacker
   ↓
iptables MANGLE -> NFQUEUE 2 -> Suricata
   ↓ (jika ACCEPT / lolos)
iptables FILTER -> NFQUEUE 3 -> ML XGBoost
   ↓ (jika ACCEPT / lolos)
DVWA Server
```

---

### Terminal 1 — Setup Hybrid & Jalankan Suricata

```bash
# Langkah 1: Reset environment
./runner_scripts/operation/cleanup.sh
./runner_scripts/operation/reset_logs.sh

# Langkah 2: Atur Cascading IPTables (Mangle + Filter)
./runner_scripts/firewall-scripts/setup_hybrid.sh

# Langkah 3: Jalankan Suricata (Garda 1) + pantau alert
./runner_scripts/firewall-scripts/run_suricata.sh
```

---

### Terminal 2 — Jalankan ML Runner (Garda 2)

```bash
./runner_scripts/firewall-scripts/run_ml.sh
```

> [!IMPORTANT]
> Pada skenario Hybrid, ML Runner hanya akan mencetak output **jika paket berhasil lolos dari Suricata**. Ini adalah momen pembuktian utama: payload yang tidak dikenali oleh rule Suricata masih bisa dicegat oleh ML.

---

### Terminal 4 — Inspeksi Dua Lapisan Sekaligus

```bash
# Ini adalah perintah terpenting untuk skenario Hybrid
# Pantau packet counter MANGLE (Suricata) dan FILTER (ML) bersamaan
./runner_scripts/target-scripts/monitor_iptables.sh
```

Untuk inspeksi payload raw yang melintas:
```bash
./runner_scripts/target-scripts/monitor_raw_traffic.sh
```

---

### Terminal 3 — Kirim Traffic

```bash
./runner_scripts/attacker-scripts/send_attack.sh
./runner_scripts/attacker-scripts/send_normal.sh
```

---

### Hasil yang Diharapkan (Skenario 3)

| Kondisi Payload | Terminal 1 (Suricata) | Terminal 2 (ML) | Terminal 3 (Attacker) |
|---|---|---|---|
| **Known SQLi** (ada di rules) | Cetak alert | **Diam** (paket sudah DROP di Mangle) | `[DROP] BLOCKED` |
| **Obfuscated / Zero-day SQLi** | **Diam** (False Negative) | Cetak deteksi + DROP | `[DROP] BLOCKED` |
| **Traffic Normal** | Diam | Cetak ACCEPT | `[PASS] LOLOS` |

> [!TIP]
> **Ini adalah momen paling kritis untuk Bab 4 Skripsi.** Screenshot kondisi di mana Terminal 1 diam (Suricata miss) tetapi Terminal 2 mencetak deteksi adalah bukti nyata keunggulan arsitektur Hybrid.

---

## Perintah Tambahan (Ad-hoc)

### Cek status iptables secara manual
```bash
# Lihat tabel filter
sudo iptables -t filter -L -v -n --line-numbers

# Lihat tabel mangle
sudo iptables -t mangle -L -v -n --line-numbers
```

### Cek apakah Suricata masih berjalan
```bash
sudo ps aux | grep suricata
# atau
sudo suricatasc -c "iface-stat" 2>/dev/null
```

### Lihat 20 alert Suricata terakhir
```bash
sudo tail -n 20 /var/log/suricata/fast.log
```

### Lihat detail log Suricata (JSON, untuk analisis mendalam)
```bash
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool
```

### Test konektivitas DVWA secara manual
```bash
curl -v -H "Cookie: PHPSESSID=xxxxx; security=low" \
  "http://172.17.0.2/vulnerabilities/sqli/?id=1&Submit=Submit"
```

---

## Struktur File Runner Scripts

```
runner_scripts/
├── README.md                          ← Panduan ini
│
├── operation/
│   ├── cleanup.sh                     ← Reset IPTables + Kill proses
│   └── reset_logs.sh                  ← Kosongkan semua log
│
├── firewall-scripts/
│   ├── setup_suricata_only.sh         ← Setup Skenario 1
│   ├── setup_ml_only.sh               ← Setup Skenario 2
│   ├── setup_hybrid.sh                ← Setup Skenario 3
│   ├── run_suricata.sh                ← Jalankan Suricata + tail log
│   └── run_ml.sh                      ← Jalankan ML Runner real-time
│
├── attacker-scripts/
│   ├── send_attack.sh                 ← Kirim sqli_payloads.txt via curl
│   └── send_normal.sh                 ← Kirim dvwa_wordlist.txt via curl
│
└── target-scripts/
    ├── monitor_web_log.sh             ← docker logs -f dvwa
    ├── monitor_iptables.sh            ← watch packet counter
    └── monitor_raw_traffic.sh         ← tcpdump + highlight SQLi
```
