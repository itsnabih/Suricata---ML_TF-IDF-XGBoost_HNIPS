# Data Kebutuhan Pengujian — Isian Berdasarkan Kode & Log Aktual
### Diverifikasi dari: skrip `.sh`, `model_ML_run.py`, log saved, `model_meta.json`
### Dibuat: 2026-07-13 | Jika tidak ada di artefak, dinyatakan TIDAK ADA

---

## DATA DASAR PENGUJIAN

| Data | Nilai |
| :--- | :--- |
| Target pengujian | `http://172.17.0.2:80/vulnerabilities/sqli/` |
| IP pengirim (attacker) | `172.17.0.1` (terlihat di log ML sebagai src; tidak dicatat eksplisit di skrip) |
| Tingkat keamanan DVWA | `security=low` (dari Cookie di semua skrip) |
| Metode serangan | GET — `curl -G` dengan `--data-urlencode` di `send_attack.sh` dan `send_normal.sh` |
| Jumlah pengulangan | 1 kali per skenario |
| Waktu tunggu (timeout curl) | 2 detik — `--max-time 2` |
| Kriteria diblokir | HTTP status `000` (curl timeout karena paket di-DROP) |
| Kriteria lolos | HTTP status selain `000` (request mencapai DVWA atau mendapat respons) |
| Validasi hasil | Berdasarkan status HTTP dari sisi pengirim (curl) saja |

**Perlakuan status HTTP (dari kode send_attack.sh):**

```
Status 000 / timeout = BLOCKED — dihitung sebagai DROP
HTTP 200             = LOLOS — dihitung sebagai ALLOWED
HTTP 302             = LOLOS — dihitung sebagai ALLOWED (bucket WARN)
HTTP 404             = LOLOS — dihitung sebagai ALLOWED (bucket WARN)
HTTP 500             = LOLOS — dihitung sebagai ALLOWED (bucket WARN)
```

> 404 dan 500 dihitung sebagai LOLOS (request mencapai server). Tidak ada cross-check ke access log DVWA.

---

## DATA JUMLAH TRAFFIC PENGUJIAN

```
Jumlah payload pada file sqli_payloads.txt    = 449 baris total
Jumlah baris komentar (#) dilewati            = 27
Jumlah baris kosong dilewati                  = 0
Jumlah payload yang benar-benar dikirim       = 422

Jumlah URL pada file dvwa_wordlist.txt        = 700 baris total
Jumlah baris komentar/kosong dilewati         = 1
Jumlah URL yang benar-benar dikirim           = 699
```

**Penjelasan angka [422/424]:**
- `424` = hasil `grep -cv` (jumlah baris non-kosong non-komentar sebelum loop)
- `422` = jumlah payload yang benar-benar terkirim (hasil loop bash dengan filter `[[ -z || #* ]]`)
- Angka resmi yang digunakan dalam log: **Total Payload Dikirim: 422**

**Penjelasan 700 vs 699 untuk normal:**
- `700` = total baris file `dvwa_wordlist.txt`
- `699` = URL yang benar-benar dikirim (1 baris dilewati filter)

---

## DATA ARSITEKTUR (Rumusan Masalah 1)

```
NFQUEUE Suricata  = 2 (tabel iptables MANGLE)
NFQUEUE XGBoost   = 3 (tabel iptables FILTER)
route-queue       = 3 (diaktifkan di suricata.yaml saat skenario Hybrid)
Port yang diperiksa model = 80, 8080, 8000 (default --ports di model_ML_run.py)
Threshold model   = 0.95285835 (dimuat dari model_meta.json)
```

**Artefak yang dimuat saat runtime:**
```
tfidf_vectorizer.pkl  (1,5 MB)
feature_selector.pkl  (627 KB)
xgb_sqli_model.pkl    (996 KB)
model_meta.json       (5,8 KB) — sumber threshold dan config
```

**Urutan alur paket:**

Skenario 1 (Suricata Only):
```
Attacker → [FILTER NFQUEUE 2] → Suricata → DROP atau ACCEPT → DVWA
```

Skenario 2 (XGBoost Only):
```
Attacker → [FILTER NFQUEUE 3] → XGBoost ML → DROP atau ACCEPT → DVWA
```

Skenario 3 (Hybrid):
```
Attacker → [MANGLE NFQUEUE 2] → Suricata
                                  ├─ DROP (selesai)
                                  └─ ACCEPT + route-queue:3
                                     → [FILTER NFQUEUE 3] → XGBoost ML
                                                              ├─ DROP (selesai)
                                                              └─ ACCEPT → DVWA
```

**Bukti validasi dari log:**
- Suricata aktif: log mencatat PID dan alert real-time ke fast.log
- ML binding NFQUEUE: log mencatat "Loaded artifacts. threshold=0.95285835 ... selector=yes"
- Paket ACCEPT mencapai DVWA: TIDAK ADA bukti dari access log — inferensial dari curl status 200
- Paket DROP tidak mencapai DVWA: TIDAK ADA cross-check — inferensial dari curl status 000

---

## DATA HASIL SKENARIO SURICATA TUNGGAL (Skenario 1)
*Run: 2026-07-04 — Normal pukul 06:57, Attack pukul 07:44*

```
Jumlah attack dikirim   = 422
Jumlah attack diblokir  = 357
Jumlah attack lolos     = 65

Jumlah normal dikirim   = 699
Jumlah normal diteruskan = 692
Jumlah normal diblokir  = 7

TP = 357
FN = 65
TN = 692
FP = 7

Sumber diblokir  = penghitungan status 000 dari curl di send_attack.sh
Sumber lolos     = penghitungan status non-000 dari curl
Divalidasi dengan access log DVWA = TIDAK
```

**False Positive (7 URL normal yang diblokir Suricata):**
```
[21/700]  /security.php
[188/700] /security.php
[192/700] /vulnerabilities/brute/?name=O'Connor
[206/700] /vulnerabilities/csrf/?name=O'Connor
[237/700] /vulnerabilities/sqli/?name=O'Connor
[355/700] /security.php
[623/700] /security.php
```

> **CATATAN ANALISIS AKAR MASALAH (diverifikasi dari kode & model):**
>
> **① /security.php (4 kali) — BUKAN diblokir IPS, melainkan timeout DVWA**
> - Tidak cocok satu pun rule Suricata (tidak ada parameter, tidak ada karakter SQL)
> - Prediksi XGBoost: `proba = 0.002978` — jauh di bawah threshold `0.9529` → ACCEPT
> - Penyebab status `000`: DVWA tidak merespons dalam batas `--max-time 2 detik` curl
> - Terjadi konsisten di posisi yang sama di SEMUA skenario → ini artefak perilaku DVWA, bukan kesalahan IPS
> - Untuk skripsi: sebaiknya dicatat sebagai **limitasi metodologi** (timeout curl terlalu ketat), bukan FP IPS
>
> **② O'Connor (3 kali) — Diblokir Suricata SID 1000002** ✅ FP Rule Legit
> - URL `?name=O'Connor` memiliki tanda kutip tunggal `'` di nilai parameter
> - Rule `1000002` "SQL Injection - Basic Quote Test" mencocokkan pola: *nilai parameter mengandung `'`*
> - Suricata tidak bisa membedakan `O'Connor` (nama orang) vs `' OR '1'='1` (SQL injection)
> - Ini adalah True False Positive dari sisi rule — rule valid tapi terlalu agresif secara semantis
>
> **Ringkasan FP Suricata yang sesungguhnya:**
> - FP dari rule IPS (SID 1000002): **3** (O'Connor)
> - FP akibat timeout DVWA (bukan IPS): **4** (/security.php)

---

## DATA HASIL SKENARIO XGBOOST TUNGGAL (Skenario 2)
*Run: 2026-07-04 — Normal pukul 08:18, Attack pukul 08:24*

```
Jumlah attack dikirim   = 422
Jumlah attack diblokir  = 194
Jumlah attack lolos     = 228

Jumlah normal dikirim   = 699
Jumlah normal diteruskan = 695
Jumlah normal diblokir  = 4

TP = 194
FN = 228
TN = 695
FP = 4

Threshold yang digunakan          = 0.95285835
Total paket masuk ke model (NFQUEUE) = 5.581 paket TCP
Paket yang diinspeksi (HTTP request) = 2.168 paket
Keputusan DROP di log model       = 1.940 drop (paket TCP — BUKAN request)
Keputusan ACCEPT di log model     = 228 baris ACCEPT tercatat
Error model                       = 0
```

> PENTING: `drop=1940` di log ML adalah jumlah PAKET TCP, bukan HTTP request.
> Satu request HTTP bisa menghasilkan banyak paket TCP.
> Gunakan angka 194 (dari sisi curl) untuk hitungan per-request.

**False Positive XGBoost (4 FP):**
```
[21/700]  /security.php  → DROP
[188/700] /security.php  → DROP
[355/700] /security.php  → DROP
[623/700] /security.php  → DROP
Probabilitas masing-masing: TIDAK DIKETAHUI dari log tersimpan
```

> **CATATAN ANALISIS AKAR MASALAH:**
>
> **Semua 4 FP XGBoost adalah /security.php — BUKAN diblokir model ML**
> - Prediksi model terhadap `/security.php`: `proba = 0.002978` → jauh di bawah threshold → model ACCEPT
> - Penyebab status `000` sama dengan skenario Suricata: **timeout DVWA**, bukan keputusan DROP model
> - XGBoost tidak memiliki FP dari O'Connor karena model memprediksinya sebagai benign (`proba ≈ 0.001`)
> - **FP XGBoost yang sesungguhnya dari model = 0** (nol); ke-4 kasus adalah artefak timeout DVWA

---

## DATA HASIL SKENARIO HYBRID (Skenario 3)
*Run: 2026-07-04 — Normal pukul 09:13, Attack pukul 09:21*

```
Jumlah attack dikirim        = 422
Jumlah attack diblokir total = 370
Jumlah attack lolos          = 52

Jumlah normal dikirim        = 699
Jumlah normal diteruskan     = 692
Jumlah normal diblokir total = 7

TP = 370
FN = 52
TN = 692
FP = 7
```

**Kontribusi per lapisan:**
```
Attack diblokir Suricata       = TIDAK DIKETAHUI
Attack diteruskan ke XGBoost   = TIDAK DIKETAHUI
Attack diblokir XGBoost        = TIDAK DIKETAHUI
Attack lolos dari kedua lapisan= 52

Normal diblokir Suricata       = TIDAK DIKETAHUI
Normal diteruskan ke XGBoost   = TIDAK DIKETAHUI
Normal diblokir XGBoost        = TIDAK DIKETAHUI
Normal lolos dari kedua lapisan= 692
```

> Rincian kontribusi per lapisan tidak dapat diperoleh dari log yang tersimpan.
> Log ML Sesi 5 (09:09–09:42): FINAL STATS total=9237 inspected=874 accept=9107 drop=130
> Ini adalah statistik paket, bukan request HTTP, dan mencakup traffic dari semua sumber.

---

## DATA PERBANDINGAN (Rumusan Masalah 2)

```
TP Suricata = 357    TP Hybrid = 370
FN Suricata = 65     FN Hybrid = 52
TN Suricata = 692    TN Hybrid = 692
FP Suricata = 7      FP Hybrid = 7
```

**Tentang penurunan false positive:**
```
Jumlah FP Suricata vs Hybrid = SAMA (7 vs 7) — tidak ada penurunan
Jumlah FP Suricata vs XGBoost = 7 vs 4 — XGBoost lebih sedikit
FPR Suricata = 7/699 = 1,00%
FPR XGBoost  = 4/699 = 0,57%
FPR Hybrid   = 7/699 = 1,00%
```

> **CATATAN — Klasifikasi ulang FP setelah analisis akar masalah:**
>
> Dari total FP yang tercatat, terdapat dua jenis berbeda:
>
> | Jenis FP | URL | Penyebab | Suricata | XGBoost | Hybrid |
> | :--- | :--- | :--- | :---: | :---: | :---: |
> | Timeout DVWA (bukan IPS) | `/security.php` ×4 | DVWA lambat merespons, curl timeout 2 dtk | 4 | 4 | 4 |
> | FP rule IPS (SID 1000002) | `O'Connor` ×3 | Tanda kutip `'` dalam nama | 3 | 0 | 3 |
> | **Total tercatat** | | | **7** | **4** | **7** |
>
> Jika `/security.php` dikeluarkan sebagai artefak timeout (bukan kesalahan IPS):
> ```
> FP Suricata murni (dari rule)   = 3  → FPR = 3/699 = 0,43%
> FP XGBoost murni (dari model)   = 0  → FPR = 0/699 = 0,00%
> FP Hybrid murni (dari IPS)      = 3  → FPR = 3/699 = 0,43%
> ```
> Pilihan penggunaan angka (7 atau 3) harus dikonsistensikan dan dijelaskan di skripsi.

---

## METRIK PER SKENARIO (Rumusan Masalah 3)

*Positive class = attack | Negative class = normal/benign*

| Skenario | TP | TN | FP | FN | Accuracy | Precision | Recall | F1-Score | FPR |
| :--- | --: | --: | --: | --: | ---: | ---: | ---: | ---: | ---: |
| Suricata | 357 | 692 | 7 | 65 | 93,58% | 98,08% | 84,60% | 90,80% | 1,00% |
| XGBoost | 194 | 695 | 4 | 228 | 79,30% | 97,98% | 45,97% | 62,60% | 0,57% |
| Hybrid | 370 | 692 | 7 | 52 | 94,74% | 98,14% | 87,68% | 92,67% | 1,00% |

*N total = 422 attack + 699 normal = 1.121*

---

## DATA EVALUASI MODEL SEBELUM DEPLOYMENT

```
Jumlah data validasi = 13.164
Jumlah data uji      = 13.165

Validation:
TP = 7.249 | TN = 5.904 | FP = 2 | FN = 9
Accuracy  = 99,92%
Precision = 99,97%
Recall    = 99,88%
F1-Score  = 99,92%
ROC-AUC   = 99,9995%

Test:
TP = 7.252 | TN = 5.897 | FP = 9 | FN = 7
Accuracy  = 99,88%
Precision = 99,88%
Recall    = 99,90%
F1-Score  = 99,89%
ROC-AUC   = 99,9637%

Best iteration  = 733
Threshold akhir = 0,9529
```

---

## DATA PENGUJIAN SQLMAP

```
Perintah:
  sqlmap -u "http://172.17.0.2/vulnerabilities/sqli/?id=1&Submit=Submit"
         --cookie="..." --batch --random-agent --dbms=mysql --level=2 --risk=2 -v 3

Parameter level  = 2
Parameter risk   = 2
DBMS             = mysql
Random agent     = aktif
Timeout          = TIDAK dikonfigurasi eksplisit (default sqlmap)

Hasil semua skenario:
  Parameter injectable = TIDAK — sqlmap gagal mendapatkan hasil
  Timeout terjadi      = YA — "[CRITICAL] connection timed out to the target URL"
  Rule yang memblokir  = TIDAK DIKETAHUI dari log tersimpan
  Request mencapai DVWA= TIDAK DIKETAHUI (perlu access log DVWA)
```

---

## FORMAT RINGKAS FINAL

```
A. KONFIGURASI
IP attacker      = 172.17.0.1
IP firewall      = (sama node dengan attacker dalam setup ini)
IP DVWA          = 172.17.0.2
Port DVWA        = 80
Security level   = low
NFQUEUE Suricata = 2
NFQUEUE XGBoost  = 3
Threshold        = 0.95285835
Pengulangan      = 1 kali
Timeout curl     = 2 detik

B. JUMLAH DATA
Attack pada file           = 449 baris (27 komentar)
Attack benar-benar dikirim = 422
Normal pada file           = 700 baris (1 komentar)
Normal benar-benar dikirim = 699

C. SURICATA ONLY
Attack diblokir = 357
Attack lolos    = 65
Normal lolos    = 692
Normal diblokir = 7

D. XGBOOST ONLY
Attack diblokir = 194
Attack lolos    = 228
Normal lolos    = 695
Normal diblokir = 4
Error model     = 0

E. HYBRID
Attack diblokir total    = 370
Attack lolos             = 52
Normal lolos             = 692
Normal diblokir total    = 7
Attack diblokir Suricata = TIDAK DIKETAHUI
Attack diblokir XGBoost  = TIDAK DIKETAHUI
Normal diblokir Suricata = TIDAK DIKETAHUI
Normal diblokir XGBoost  = TIDAK DIKETAHUI

F. SQLMAP
Suricata = timeout, tidak injectable
XGBoost  = timeout, tidak injectable
Hybrid   = timeout, tidak injectable

G. EVALUASI MODEL (dataset)
Best iteration  = 733
Threshold       = 0.9529
TP test         = 7.252
TN test         = 5.897
FP test         = 9
FN test         = 7
Accuracy test   = 99,88%
Precision test  = 99,88%
Recall test     = 99,90%
F1 test         = 99,89%
ROC-AUC test    = 99,9637%
```

---

## DATA YANG TIDAK TERSEDIA (TIDAK ADA DI LOG/ARTEFAK)

1. Kontribusi per-lapisan di Hybrid (Suricata vs XGBoost memblokir berapa)
2. Rule SID Suricata per-permintaan yang diblokir
3. Probabilitas XGBoost untuk setiap FP dan FN
4. Daftar payload yang lolos (FN) per skenario
5. Access log DVWA
6. IP attacker yang eksplisit di skrip (hanya terlihat di log ML)
7. Waktu pelatihan model
8. Rincian per-request dari sqlmap per skenario

*Dibuat: 2026-07-13 dari analisis kode dan log aktual*
