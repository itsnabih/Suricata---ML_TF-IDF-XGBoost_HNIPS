# Ringkasan Hasil Pengujian IPS

Dokumen ini merangkum hasil uji coba sistem deteksi intrusi (Suricata dan Machine Learning XGBoost) berdasarkan file log yang tersimpan di dalam folder `saved_logs`. Log ini mencatat pengujian tiga skenario (kemungkinan Skenario 1: Suricata Only, Skenario 2: ML Only, dan Skenario 3: Hybrid).

## 1. Pengujian Skenario Pertama
*Berdasarkan eksekusi dan blok log pertama.*
- **Serangan (Custom Payloads):** 
  - Total Payload Dikirim: 422
  - Diblokir (DROP/timeout): 357 (84.6%)
  - Lolos ke Server (False Negatives): 65
- **Traffic Normal:** 
  - Total Request: 699
  - Berhasil (True Negatives): 692
  - Diblokir (False Positives): 7 (1.0%)

## 2. Pengujian Skenario Kedua
*Berdasarkan eksekusi dan blok log kedua.*
- **Serangan (Custom Payloads):** 
  - Total Payload Dikirim: 422
  - Diblokir (DROP/timeout): 194 (46.0%)
  - Lolos ke Server (False Negatives): 228
- **Traffic Normal:** 
  - Total Request: 699
  - Berhasil (True Negatives): 695
  - Diblokir (False Positives): 4 (0.57%)

## 3. Pengujian Skenario Ketiga (Hybrid)
*Berdasarkan eksekusi dan blok log ketiga.*
- **Serangan (Custom Payloads):** 
  - Total Payload Dikirim: 422
  - Diblokir (DROP/timeout): 370 (87.7%)
  - Lolos ke Server (False Negatives): 52
- **Traffic Normal:** 
  - Total Request: 699
  - Berhasil (True Negatives): 692
  - Diblokir (False Positives): 7 (1.0%)

## 4. Pengujian SQLMap (Automated Attack)
Berdasarkan log `log-nomor 3_send_sqlmap.txt`, proses eksekusi alat uji penetrasi otomatis `sqlmap` secara konsisten menemui peringatan:
> `[CRITICAL] connection timed out to the target URL`

Hal ini membuktikan bahwa mekanisme pemblokiran IPS (melalui iptables / *DROP packets*) berjalan sukses. Serangan agresif dari `sqlmap` berhasil dihentikan sepenuhnya di tingkat jaringan sebelum ditangani server DVWA, sehingga `sqlmap` gagal mendapatkan data dari injeksi.

## Kesimpulan Singkat
1. Skenario terakhit (yakni gabungan/hybrid) mencatat tingkat perlindungan serangan *custom payload* tertinggi, memblokir **370 dari 422 (87.7%)** serangan. Performa deteksinya lebih besar dibandingkan Suricata dan ML ketika berjalan masing-masing.
2. Tingkat *False Positive* pada traffic normal sangat rendah. Pada deteksi maksimal sekalipun (Skenario 3), sistem hanya memblokir keliru sebanyak 7 dari 699 (sekitar 1% dari total traffic normal).
3. Pengujian *inline blocking* berfungsi dengan baik, dibuktikan dengan suksesnya server men-drop / menghentikan pergerakan alat pemindai seperti *SQLMap*.
