# Panduan Pengujian Manual & Inspeksi Real-Time (Hybrid IPS)

Dokumen ini berisi panduan detail untuk melakukan pengujian manual dari terminal dan melakukan inspeksi *real-time* di setiap *node*. Pengujian ini menyimulasikan cara kerja dari skrip `run_tests.sh` menggunakan `curl` dan *wordlist* (daftar payload).

## Persiapan Umum & Topologi Terminal

Sebelum memulai, sangat direkomendasikan untuk membuka **4 tab/window terminal (Node)** secara bersamaan agar aliran trafik dan deteksi terlihat secara *real-time*:

1. **Terminal 1 (Firewall - Suricata)**: Untuk eksekusi dan memantau log Suricata.
2. **Terminal 2 (Firewall - ML)**: Untuk eksekusi dan memantau *Machine Learning Runner*.
3. **Terminal 3 (Attacker)**: Untuk menjalankan `curl` dan menembakkan *payload*.
4. **Terminal 4 (Target / Server)**: Untuk memantau *log* akses pada Web Server (Docker DVWA) dan *counter* IPTables.

**Catatan**: Pastikan Cookie di terminal Attacker valid. Sesuaikan variabel `COOKIE` dengan sesi DVWA Anda jika sudah *expired*.

---

## 1. Skenario 1: Suricata Only (Signature-Based)

Pada skenario ini, kita hanya mengaktifkan pertahanan lapis pertama.

### A. Setup di Terminal 1 (Firewall - Suricata)
Bersihkan *rules* IPTables dari pengujian sebelumnya, set *routing* ke Suricata (Queue 2), dan jalankan *tail* untuk inspeksi.

```bash
# 1. Bersihkan IPTables
sudo iptables -t filter -F
sudo iptables -t mangle -F
sudo pkill -x suricata
sudo pkill -f model_ML_run.py

# 2. Redirect traffic HTTP ke Suricata (Queue 2)
sudo iptables -I OUTPUT -p tcp -d 172.17.0.2 --dport 80 -j NFQUEUE --queue-num 2
sudo iptables -I INPUT -p tcp -s 172.17.0.2 --sport 80 -j NFQUEUE --queue-num 2

# 3. Bersihkan log lama & jalankan Suricata di background
sudo truncate -s 0 /var/log/suricata/fast.log
sudo suricata -c /etc/suricata/suricata.yaml -q 2 -D

# 4. Inspeksi Real-Time: Pantau log alert Suricata
tail -f /var/log/suricata/fast.log
```

### B. Inspeksi di Terminal 4 (Target / Server)
Pantau apakah *traffic* berhasil menembus aplikasi.
```bash
# Pantau log realtime docker DVWA
sudo docker logs -f dvwa
```

### C. Eksekusi Serangan di Terminal 3 (Attacker)
Simulasikan serangan dari `sqli_payloads.txt` secara otomatis menggunakan bash *loop*.

```bash
# Definisikan Cookie (Sesuaikan jika sudah expired)
COOKIE="PHPSESSID=vgaqqh5gc08093scgsg7lkmi20; security=low"

# Eksekusi payload satu per satu dari file (dengan delay 1 detik)
while IFS= read -r payload; do
    [[ -z "$payload" || "$payload" == \#* ]] && continue
    echo "[*] Mengirim: $payload"
    curl -s --max-time 2 -w "\nHTTP Status: %{http_code}\n" \
        -G "http://172.17.0.2/vulnerabilities/sqli/" \
        --data-urlencode "id=$payload" \
        --data-urlencode "Submit=Submit" \
        -H "Cookie: $COOKIE"
    echo "--------------------------------"
    sleep 1
done < sqli_payloads.txt
```

### D. Hasil Inspeksi yang Diharapkan
- **Terminal 1**: Anda akan melihat *alert* SQLi bermunculan setiap kali *payload* berbahaya dikirim.
- **Terminal 4**: Permintaan berbahaya tidak akan tercatat dalam akses log DVWA karena paket telah di-DROP sebelum mencapai server web.
- **Terminal 3**: Output dari perintah `curl` akan menampilkan koneksi *timeout* (karena paket di-DROP secara diam-diam / *blackhole*).

---

## 2. Skenario 2: ML Only (Anomaly-Based)

Pada skenario ini, kita menonaktifkan Suricata dan mendelegasikan semua *traffic* ke ML *Classifier*.

### A. Setup di Terminal 2 (Firewall - ML)
```bash
# 1. Bersihkan IPTables dan proses sebelumnya
sudo iptables -t filter -F
sudo iptables -t mangle -F
sudo pkill -x suricata
sudo pkill -f model_ML_run.py

# 2. Redirect traffic HTTP ke Machine Learning (Queue 3)
sudo iptables -I OUTPUT -p tcp -d 172.17.0.2 --dport 80 -j NFQUEUE --queue-num 3
sudo iptables -I INPUT -p tcp -s 172.17.0.2 --sport 80 -j NFQUEUE --queue-num 3

# 3. Inspeksi Real-Time: Jalankan ML di foreground dengan parameter log-payloads
sudo python3 model_ML_run.py --queue 3 --log-payloads
```

### B. Inspeksi di Terminal 4 (Target / Server)
```bash
# Tetap pantau log web server
sudo docker logs -f dvwa
```

### C. Eksekusi Serangan di Terminal 3 (Attacker)
Jalankan bash *loop* dengan `curl` persis seperti pada **Langkah 1.C**.

### D. Hasil Inspeksi yang Diharapkan
- **Terminal 2**: Akan muncul teks secara *real-time* untuk tiap *request* HTTP, mencakup *Payload* yang diekstrak, Nilai Probabilitas Anomali, dan Keputusan Akhir (DROP/ACCEPT).
- **Terminal 4**: *Traffic* bersih akan masuk ke *log*. *Traffic* anomali akan terblokir.
- **Terminal 3**: *Curl* untuk *payload* berbahaya akan *timeout*.

---

## 3. Skenario 3: Hybrid (Suricata + ML)

Pada skenario pamungkas ini, kita menggunakan *Cascading Iptables*. Suricata berada di garda depan, jika lolos, masuk ke garda belakang (Machine Learning).

### A. Setup di Terminal 1 & 2 (Firewall)
Kali ini, iptables menggunakan *table* yang berbeda: `mangle` untuk Queue 2 (Suricata) dan `filter` untuk Queue 3 (ML).

**Di Terminal 1 (Konfigurasi & Suricata):**
```bash
# 1. Reset Environment
sudo iptables -t filter -F
sudo iptables -t mangle -F
sudo pkill -x suricata
sudo pkill -f model_ML_run.py

# 2. Setup Cascading Iptables
# Garda Pertama: Suricata di tabel MANGLE (Dieksekusi lebih dulu)
sudo iptables -t mangle -I OUTPUT -p tcp -d 172.17.0.2 --dport 80 -j NFQUEUE --queue-num 2
sudo iptables -t mangle -I INPUT -p tcp -s 172.17.0.2 --sport 80 -j NFQUEUE --queue-num 2

# Garda Kedua: ML di tabel FILTER (Dieksekusi jika Mangle merespons ACCEPT)
sudo iptables -t filter -I OUTPUT -p tcp -d 172.17.0.2 --dport 80 -j NFQUEUE --queue-num 3
sudo iptables -t filter -I INPUT -p tcp -s 172.17.0.2 --sport 80 -j NFQUEUE --queue-num 3

# 3. Jalankan Suricata dan pantau
sudo truncate -s 0 /var/log/suricata/fast.log
sudo suricata -c /etc/suricata/suricata.yaml -q 2 -D
tail -f /var/log/suricata/fast.log
```

**Di Terminal 2 (ML Runner):**
```bash
# Jalankan ML Runner untuk menampung tangkapan garda belakang
sudo python3 model_ML_run.py --queue 3 --log-payloads
```

### B. Inspeksi di Terminal 4 (Target / Server)
Sebagai tambahan dari *docker logs*, mari pantau hitungan *packet drop/accept* dari kedua lapis *iptables*:
```bash
# Memantau paket iptables secara real-time setiap 1 detik
watch -n 1 'echo "=== GARDA 1 (SURICATA) ===" && sudo iptables -t mangle -L -v -n && echo "=== GARDA 2 (ML) ===" && sudo iptables -t filter -L -v -n'
```
*(Buka tab baru atau berhentikan sementara perintah watch untuk melihat docker logs `sudo docker logs -f dvwa`)*

### C. Eksekusi Serangan di Terminal 3 (Attacker)
Jalankan bash *loop* dengan `curl` kembali seperti pada **Langkah 1.C**.
*(Tips: Coba gunakan serangan Obfuscated SQLi yang tidak dikenali rules Suricata untuk melihat fungsi garda kedua).*

### D. Hasil Inspeksi yang Diharapkan (Momen Pembuktian Hybrid)
- **Kondisi 1: Payload Dikenali (*Known Signature*)**: 
  - Suricata di Terminal 1 akan bereaksi mencetak *alert*.
  - Di Terminal 2, ML Runner **TIDAK AKAN** mencetak apa-apa, karena paket sudah dihancurkan di lapisan `mangle`.
- **Kondisi 2: Payload Obfuscated / Tidak Dikenali (*Zero-day*)**: 
  - Suricata di Terminal 1 akan **diam saja** (*False Negative*). Paket dilepas (ACCEPT).
  - ML Runner di Terminal 2 akan mendeteksi *request* tersebut karena pola fiturnya merujuk pada SQLi (*Anomaly Detection*), lalu mencetak deteksi dan melakukan DROP paket di tabel `filter`.
- **Terminal 3**: Penyerang selalu gagal (*timeout/reset*).
- **Terminal 4 (Watch)**: Anda dapat melihat *packet counter* di `mangle` naik untuk tangkapan Suricata, dan *packet counter* di `filter` naik untuk tangkapan ML.

---

Dengan langkah-langkah di atas, Anda dapat melakukan tangkapan layar (*screenshot*) pada keempat terminal tersebut sekaligus sebagai dokumentasi Bab 4 Skripsi yang sangat kuat, membuktikan bahwa integrasi *inline IPS* ini bekerja secara harmonis.
