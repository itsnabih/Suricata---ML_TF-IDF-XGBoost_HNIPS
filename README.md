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

Penelitian ini memiliki tiga skenario pengujian utama untuk membandingkan performa model Hibrida, yang seluruhnya otomatis dijalankan melalui skrip Bash.

**Cara Menjalankan Pengujian:**
```bash
sudo ./run_tests.sh
```

**Skenario yang Berjalan Secara Otomatis:**
1. **Skenario 1: Suricata Only**
   - Hanya Suricata yang berjalan mendengarkan NFQUEUE. 
   - Berfungsi untuk melihat seberapa banyak serangan SQLMap yang bisa di- *block* oleh *rule* statis.
2. **Skenario 2: ML Only**
   - Hanya skrip Python XGBoost (`model_ML_run.py`) yang berjalan pada NFQUEUE.
   - Menguji keandalan deteksi ML secara murni dengan akurasi model V2 yang mencapai di atas 99%.
3. **Skenario 3: Hybrid (Suricata + ML)**
   - Menggabungkan keduanya. Paket masuk akan melewati Suricata terlebih dahulu. Jika gagal terdeteksi (lolos *signature*), paket akan diteruskan ke NFQUEUE Python untuk dianalisis oleh AI. Ini merupakan arsitektur utama penelitian ini.

### Hasil Log & Analisis
Setiap selesai menjalankan skenario, skrip `run_tests.sh` akan secara otomatis menyalin dan mengekspor seluruh log aktivitas dari Docker DVWA, Log Iptables, Suricata, dan *stdout* ML ke dalam direktori:
`data-hasil_pengujian/`

Struktur *output* pengujian:
```text
data-hasil_pengujian/
├── 01_suricata_only/
├── 02_ml_only/
└── 03_hybrid/
    ├── firewall/  # (Log iptables, log Suricata eve.json/fast.log, dll.)
    ├── target/    # (Log akses HTTP dari container DVWA)
    └── user/      # (Log aktivitas serangan dari SQLmap)
```

Anda dapat menggunakan log-log tersebut untuk melengkapi hasil Bab 4 (Implementasi) dan Bab 5 (Pengujian) Skripsi Anda, membuktikan bahwa **traffic SQLMap benar-benar berhasil diblokir (DROP)** di level jaringan!
