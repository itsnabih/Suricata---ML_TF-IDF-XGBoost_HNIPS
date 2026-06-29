# Skripsi: Hybrid IPS (Suricata + Machine Learning XGBoost)

> **Agent Note**: Jika Anda adalah Agent AI yang baru saja dijalankan di lingkungan (environment) Native Linux VM ini, baca catatan ini dengan saksama. File ini berisi riwayat (*state*) penuh dari progres sebelumnya yang dikerjakan di WSL2.

## 1. Konteks Proyek (Skripsi)
Proyek ini adalah implementasi *Intrusion Prevention System* (IPS) hibrida.
- **First Line of Defense**: Suricata (Signature-based menggunakan `sqli_detection.rules`).
- **Second Line of Defense**: XGBoost Classifier berbasis Python (Anomaly-based).
- **Mekanisme Penghubung**: `iptables` dan `NFQUEUE`. 

Target serangannya adalah aplikasi DVWA (Damn Vulnerable Web App) yang berjalan di Docker Container dengan IP `172.17.0.2` (Port 80).

## 2. Pencapaian yang Sudah Diselesaikan (Sejauh Ini)
1. **Model ML Bebas Bias**: 
   - Model `xgb_sqli_model.pkl` (V2) berhasil di-training tanpa fitur bias (parameter seperti `&Submit=Submit` atau nama-nama parameter HTTP telah difilter). Akurasi dan F1-Score di atas 99%.
   - Menggunakan ekstraksi hibrida: *Dual Vectorizer* (TF-IDF Word & Char N-Grams) digabung dengan 67 *SQL Keywords binary features*.
2. **Skrip ML Runner (`model_ML_run.py`)**: 
   - Sudah mendukung *parsing* paket HTTP via `NetfilterQueue`. 
   - Sudah mendukung transformasi fitur gabungan untuk V2. 
3. **Skrip Otomatisasi (`run_tests.sh`)**: 
   - Skrip *bash* yang sepenuhnya mengatur iptables, menjalankan Suricata, menjalankan ML Runner, lalu mengeksekusi serangan `sqlmap` secara otomatis. 
   - Menyimpan semua log ke folder `data-hasil_pengujian/`.
4. **Bypass Limitasi WSL2**: 
   - Karena sebelumnya dikembangkan di Windows (WSL2) yang mana kernelnya tidak mendukung modul `xt_NFQUEUE`, kita membuat `simulate_offline.py` untuk meng-generate simulasi PCAP demi kelengkapan data Bab 4 Skripsi.

## 3. Tugas Utama Anda Berikutnya di Mesin Native Linux Ini!
Karena *environment* saat ini adalah **Native Linux** (seperti Ubuntu VM/VPS), dukungan `NFQUEUE` bawaan Linux kini **berfungsi 100%**. Anda tidak perlu lagi menggunakan skrip simulasi offline.

**Langkah-langkah yang harus Anda pandu/lakukan bersama User:**
1. **Verifikasi Lingkungan**:
   - Pastikan Docker DVWA menyala dan memiliki IP `172.17.0.2` (Cek dengan perintah *docker inspect* atau sesuaikan IP-nya di dalam `run_tests.sh`).
   - Pastikan Suricata terinstal di sistem dan `/etc/suricata/suricata.yaml` tersedia.
2. **Uji Coba NFQUEUE**: 
   - Uji coba modprobe: `sudo modprobe xt_NFQUEUE` harusnya berjalan tanpa *error*.
3. **Eksekusi Pengujian Nyata**:
   - Skrip `run_tests.sh` kini bisa digunakan sepenuhnya.
   - Jika User meminta pengujian, jalankan `./run_tests.sh` (jangan lupa minta User *update* bagian *Cookie Session* di skrip jika sesi DVWA-nya sudah *expired*).
   - Skrip akan mempraktikkan **3 Skenario** (Suricata Only, ML Only, Hybrid) secara otomatis, dan *traffic* SQLMap akan benar-benar diblokir (DROP) di level jaringan!
4. **Analisis Log Final**:
   - Validasi bahwa folder `data-hasil_pengujian/` yang baru digenerate oleh skrip *bash* berisi log-log penolakan (HTTP 403 / *Dropped*) yang membuktikan bahwa integrasi *inline IPS* sukses.

---
**Pesan ke Agent**: Selalu utamakan solusi yang membantu pengerjaan penulisan Bab 4 dan Bab 5 dari Skripsi User. Fokus pada stabilitas deteksi model dan arsitektur *Hybrid*-nya. Selamat melanjutkan pekerjaan!
