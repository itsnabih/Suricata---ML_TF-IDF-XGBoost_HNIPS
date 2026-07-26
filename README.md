# Skripsi: Hybrid IPS (Suricata + Machine Learning XGBoost)

Proyek ini adalah implementasi **Intrusion Prevention System (IPS) Hibrida** yang dirancang untuk melindungi aplikasi web (DVWA) dari serangan *SQL Injection* (SQLi). Proyek ini menggabungkan kecepatan deteksi berbasis *signature* (Suricata) dan keandalan deteksi berbasis anomali (Machine Learning XGBoost).

## Arsitektur & Infrastruktur

- **First Line of Defense (Signature-based)**: Menggunakan **Suricata** dengan *ruleset* kustom (`sqli_detection.rules`).
- **Second Line of Defense (Anomaly-based)**: Menggunakan model **XGBoost Classifier** (`xgb_sqli_model.pkl`) berbasis Python. Model ini dilatih menggunakan metode hibrida: *Dual Vectorizer* (TF-IDF Word & Char N-Grams) digabung dengan 67 *SQL Keywords binary features*.
- **Mekanisme Integrasi (*Inline IPS*)**: Menggunakan **iptables** dan **NFQUEUE** (`xt_NFQUEUE` module) untuk memotong ( *intercept* ) paket HTTP di level jaringan Linux secara langsung.
- **Target Serangan**: Aplikasi web rentan **DVWA** (Damn Vulnerable Web App) yang berjalan terisolasi di dalam **Docker Container** pada alamat IP `172.17.0.2:80`.

## Persyaratan & Setup Lingkungan

Sistem ini berjalan di lingkungan **Native Linux** (seperti Ubuntu VM) agar modul kernel `xt_NFQUEUE` dapat bekerja secara optimal untuk mendrop paket. 

### 1. Instalasi Dependensi
Jalankan perintah berikut untuk menginstal seluruh dependensi sistem dan Python:
```bash
# Update & Install paket dasar
sudo apt update
sudo apt install -y python3-pip python3-dev libnetfilter-queue-dev build-essential suricata sqlmap docker.io curl

# Install library Python (XGBoost, NetfilterQueue, dll.) 
# Pastikan diinstall di level root karena eksekusi ML membutuhkan sudo
sudo pip3 install -r requirements.txt --break-system-packages
```

### 2. Penyiapan Docker Target (DVWA)
Jalankan target aplikasi web DVWA pada *container* bernama `dvwa`:
```bash
sudo docker run -d --name dvwa vulnerables/web-dvwa
```
Pastikan IP *container* adalah `172.17.0.2`. Anda bisa memastikannya dengan:
```bash
sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' dvwa
```

### 3. Konfigurasi Modul Kernel
Pastikan modul kernel IPS (Netfilter Queue) telah aktif:
```bash
sudo modprobe xt_NFQUEUE
```

---

## Persiapan Sebelum Uji Coba

Karena pengujian ini bersifat *authenticated SQLi* (menyerang halaman beranda yang butuh login), Anda harus mengambil **Session Cookie** terbaru sebelum menjalankan skrip otomatisasi.

1. **Akses DVWA**: Buka peramban (browser) di komputer Anda dan akses ke alamat IP VM Anda atau `http://localhost` (jika Anda meneruskan port Docker ke host). 
2. **Setup Database**: Login dengan kredensial default (`admin` / `password`). Masuk ke menu **Setup / Reset DB**, lalu klik *Create / Reset Database*.
3. **Turunkan Level Keamanan**: Masuk ke menu **DVWA Security**, ubah tingkat keamanan dari *Impossible* menjadi **Low**, lalu *Submit*.
4. **Dapatkan Cookie**: Buka Developer Tools (F12) -> *Application* -> *Cookies*. Salin nilai `PHPSESSID` dan `security`.
5. **Perbarui Skrip Pengujian**: Buka file `run_tests.sh` dengan teks editor. Perbarui variabel `COOKIE` dengan *session cookie* yang baru saja Anda dapatkan. Contoh:
   ```bash
   COOKIE="PHPSESSID=sesi_baru_anda_di_sini; security=low"
   ```

---

## Workflow Skenario Pengujian

Pengujian dilakukan secara **modular dengan multi-terminal**. Setiap skenario membutuhkan beberapa terminal yang menjalankan skrip secara terpisah berdasarkan peran node-nya. Seluruh skrip berada di dalam direktori `runner_scripts/`.

### Struktur Skrip (`runner_scripts/`)

| Subdirektori | Peran (Node) | Skrip | Fungsi |
|---|---|---|---|
| `firewall-scripts/` | **Firewall** | `setup_suricata_only.sh` | Setup iptables Skenario 1 (Suricata Only) |
| | | `setup_ml_only.sh` | Setup iptables Skenario 2 (ML Only) |
| | | `setup_hybrid.sh` | Setup iptables Skenario 3 (Hybrid Cascade) |
| | | `run_suricata.sh` | Menjalankan Suricata pada NFQUEUE 2 |
| | | `run_ml.sh` | Menjalankan ML Runner (XGBoost) pada NFQUEUE 3 |
| `target-scripts/` | **Target** | `monitor_web_log.sh` | Memantau log akses HTTP dari container DVWA |
| | | `monitor_iptables.sh` | Memantau counter paket iptables secara *real-time* |
| | | `monitor_raw_traffic.sh` | Menampilkan *raw* HTTP traffic via `tcpdump` |
| `attacker-scripts/` | **Attacker** | `send_attack.sh` | Mengirim payload SQLi dari file `sqli_payloads.txt` |
| | | `send_normal.sh` | Mengirim *traffic* normal dari file `dvwa_wordlist.txt` |
| | | `send_sqlmap.sh` | Menjalankan serangan `sqlmap` otomatis |
| `operation/` | **Operasional** | `cleanup.sh` | Reset environment (kill proses, flush iptables) |
| | | `reset_logs.sh` | Mengosongkan semua log (Suricata, DVWA, dll.) |

### Langkah Pengujian Per-Skenario

> **Catatan**: Sebelum memulai setiap skenario, jalankan `cleanup.sh` lalu `reset_logs.sh` untuk memastikan lingkungan bersih.

#### Skenario 1: Suricata Only
Hanya Suricata yang berjalan mendengarkan NFQUEUE. Menguji seberapa banyak serangan yang bisa di-*block* oleh *rule* statis.

| Terminal | Perintah | Keterangan |
|---|---|---|
| **Terminal 1** (Firewall) | `sudo bash firewall-scripts/setup_suricata_only.sh` | Setup iptables → NFQUEUE 2 |
| | `sudo bash firewall-scripts/run_suricata.sh` | Jalankan Suricata (real-time alert) |
| **Terminal 2** (Target) | `sudo bash target-scripts/monitor_web_log.sh` | Pantau log akses DVWA |
| **Terminal 3** (Attacker) | `sudo bash attacker-scripts/send_attack.sh` | Kirim payload SQLi |

#### Skenario 2: ML Only
Hanya skrip Python XGBoost (`model_ML_run.py`) yang berjalan pada NFQUEUE. Menguji keandalan deteksi ML secara murni.

| Terminal | Perintah | Keterangan |
|---|---|---|
| **Terminal 1** (Firewall) | `sudo bash firewall-scripts/setup_ml_only.sh` | Setup iptables → NFQUEUE 3 |
| | `sudo bash firewall-scripts/run_ml.sh` | Jalankan ML Runner (real-time log) |
| **Terminal 2** (Target) | `sudo bash target-scripts/monitor_web_log.sh` | Pantau log akses DVWA |
| **Terminal 3** (Attacker) | `sudo bash attacker-scripts/send_attack.sh` | Kirim payload SQLi |

#### Skenario 3: Hybrid (Suricata + ML)
Arsitektur utama penelitian. Paket melewati Suricata (MANGLE/Q2) terlebih dahulu, lalu diteruskan ke ML Runner (FILTER/Q3) untuk inspeksi lanjutan.

| Terminal | Perintah | Keterangan |
|---|---|---|
| **Terminal 1** (Firewall) | `sudo bash firewall-scripts/setup_hybrid.sh` | Setup iptables → MANGLE Q2 + FILTER Q3 |
| | `sudo bash firewall-scripts/run_suricata.sh` | Jalankan Suricata (Garda 1) |
| **Terminal 2** (Firewall) | `sudo bash firewall-scripts/run_ml.sh` | Jalankan ML Runner (Garda 2) |
| **Terminal 3** (Target) | `sudo bash target-scripts/monitor_web_log.sh` | Pantau log akses DVWA |
| **Terminal 4** (Attacker) | `sudo bash attacker-scripts/send_attack.sh` | Kirim payload SQLi |

> **Tips**: Untuk pengujian *False Positive*, ganti skrip attacker dengan `send_normal.sh` yang mengirimkan *traffic* normal. Request yang terblokir (status `000`/timeout) menandakan *false positive*.

### Hasil Log & Analisis
Seluruh *output* dari setiap skrip secara otomatis tersimpan ke dalam direktori `runner_scripts/saved_logs/`:

```text
runner_scripts/saved_logs/
├── attacker/   # Log serangan (send_attack, send_normal, send_sqlmap)
├── firewall/   # Log setup iptables, Suricata alert, ML Runner output
└── target/     # Log monitor iptables, web access log, raw traffic
```

Log-log tersebut dapat digunakan untuk melengkapi hasil **Bab 4 (Implementasi)** dan **Bab 5 (Pengujian)** Skripsi, membuktikan bahwa **traffic SQLi benar-benar berhasil diblokir (DROP)** di level jaringan!
