# Referensi Data Faktual — Pelatihan Model ML XGBoost
### Untuk Penulisan Bab IV Skripsi

> **Sumber data**: Diekstrak langsung dari `model_meta.json`, `model-train-v2.py`, dan komputasi aktual terhadap file dataset.  
> Semua angka telah diverifikasi dari artefak yang sudah ada di sistem.

---

## No. 1 — Nama Dataset Final yang Digunakan

**Dataset yang benar-benar dipakai saat pelatihan model adalah `datalatih.csv`.**

Buktinya ada di `model_meta.json` baris `"dataset_path": "datalatih.csv"`.

- Kode `model-train-v2.py` memiliki default `--data dataset-balanced.csv`, namun perintah yang **dieksekusi** menggunakan argumen `datalatih.csv`.
- `datalatih_v2.csv` adalah versi yang sudah di-deduplikasi secara manual, sehingga jumlah baris akhirnya sama (~87.000-an). Perbedaannya: `datalatih.csv` masih memiliki duplikat yang kemudian dibersihkan *di dalam* skrip pelatihan, sementara `datalatih_v2.csv` sudah bersih sejak awal.
- File `dataset-balanced.csv` **tidak ada** di direktori proyek — ini adalah nama *default* dari argumen CLI yang tidak dipakai.

**Kesimpulan untuk penulisan**: Gunakan `datalatih.csv` sebagai nama dataset input resmi. Jelaskan bahwa proses pembersihan (deduplication) dilakukan secara otomatis oleh skrip pelatihan, bukan secara manual terpisah.

---

## No. 2 — Jumlah Data Sebelum dan Sesudah Pembersihan

Dihitung dari `datalatih.csv`:

| Tahap Pembersihan | Jumlah Baris |
| :--- | ---: |
| **Baris mentah (raw)** | **97.072** |
| Label tidak valid (bukan `attack`/`benign`) | 0 |
| *Payload* kosong (string kosong) | 0 |
| **Setelah filter label + payload** | **97.072** |
| Duplikat dihapus (`drop_duplicates`) | 9.311 |
| **Dataset akhir (siap latih)** | **87.761** |

> Proses pembersihan dilakukan oleh fungsi `load_dataset()` di `model-train-v2.py` secara otomatis sebelum pelatihan dimulai.

---

## No. 3 — Jumlah Kelas `attack` dan `benign`

Dari dataset bersih (87.761 baris):

| Kelas | Jumlah | Persentase |
| :--- | ---: | ---: |
| **attack** | 48.389 | 55,14% |
| **benign** | 39.372 | 44,86% |
| **Total** | **87.761** | 100% |

**Dasar perhitungan `scale_pos_weight`:**

```
scale_pos_weight = benign / attack = 39.372 / 48.389 = 0,8137
```

Nilai ini dikonfirmasi oleh `model_meta.json`: `"scale_pos_weight": 0.8136513934813415`.

> Nilai `scale_pos_weight` < 1 menandakan kelas `attack` sedikit lebih banyak dari `benign`, sehingga bobot diberikan untuk menyeimbangkan pengaruh kedua kelas terhadap fungsi *loss*.

---

## No. 4 — Jumlah Data Latih, Validasi, dan Uji Secara Aktual

Proporsi yang digunakan: **70% latih — 15% validasi — 15% uji** (stratified, `random_state=42`).

Jumlah aktual (dikonfirmasi dari *confusion matrix* di `model_meta.json`):

| Subset | Total | attack | benign |
| :--- | ---: | ---: | ---: |
| **Train** | **61.432** | ~33.872 | ~27.560 |
| **Validasi** | **13.164** | 7.258 (TP+FN) | 5.906 (TN+FP) |
| **Test** | **13.165** | 7.259 (TP+FN) | 5.906 (TN+FP) |
| **Total** | **87.761** | **48.389** | **39.372** |

> Angka attack/benign pada Train adalah estimasi dari proporsi keseluruhan karena stratified split mempertahankan rasio kelas. Angka Val dan Test adalah eksakta dari confusion matrix.

---

## No. 5 — Dimensi Fitur yang Terbentuk

Ekstraksi fitur menggunakan **tiga komponen** yang digabungkan (*horizontal stack*):

| Komponen Fitur | Metode | Dimensi Maks |
| :--- | :--- | ---: |
| TF-IDF Word N-Gram | `TfidfVectorizer(analyzer='word', ngram_range=(1,3))` | 20.000 |
| TF-IDF Char N-Gram | `TfidfVectorizer(analyzer='char', ngram_range=(2,5))` | 20.000 |
| SQL Keyword Binary | Pencocokan 67 kata kunci SQL (biner 0/1) | 67 |
| **Total sebelum seleksi** | | **40.067** |

> Konfigurasi ini tercatat di `model_meta.json` bagian `"vectorizer"`: `sql_keywords_count: 67`, `word.max_features: 20000`, `char.max_features: 20000`.

---

## No. 6 — Status Seleksi Fitur

**Seleksi fitur dijalankan** karena jumlah fitur awal (40.067) **melebihi batas** `n_selected_features` (20.000).

| Parameter | Nilai |
| :--- | :--- |
| Total fitur sebelum seleksi | **40.067** |
| Metode seleksi | `SelectKBest(chi2)` |
| Jumlah fitur yang dipilih (`k`) | **20.000** |
| Total fitur setelah seleksi | **20.000** |
| Kondisi aktifasi (`total > k`) | 40.067 > 20.000 → **YA, dijalankan** |

Artefak seleksi disimpan di `feature_selector.pkl` (ukuran: 627 KB).

---

## No. 7 — Perintah Pelatihan yang Digunakan

Berdasarkan `model_meta.json` bagian `"config"`, semua parameter menggunakan **nilai bawaan** dari `TrainConfig`, kecuali `dataset_path` yang diisi `datalatih.csv`.

Perintah rekonstruksi yang ekuivalen:

```bash
python3 model-train-v2.py --data datalatih.csv
```

Tidak ada perubahan parameter non-default yang tercatat. Beberapa parameter utama yang digunakan:

| Parameter | Nilai |
| :--- | :--- |
| `--threshold-strategy` | `f1_max` (default) |
| `--max-depth` | `7` (default) |
| `--learning-rate` | `0.05` (default) |
| `--n-estimators` | `1000` (default) |
| `--early-stopping-rounds` | `50` (default) |
| `--keep-param-names` | *tidak digunakan* → `strip_param_names=True` |
| `--n-selected-features` | `20000` (default) |
| `--subsample` | `0.85` |
| `--colsample-bytree` | `0.7` |
| `--reg-lambda` | `1.0` |
| `--reg-alpha` | `0.1` |

---

## No. 8 — Versi Perangkat Lunak

| Perangkat Lunak | Versi |
| :--- | :--- |
| **Python** | 3.14.4 |
| **XGBoost** | **3.3.0** ← versi mayor ≥ 3 |
| **Scikit-learn** | 1.9.0 |
| **Pandas** | *(tidak terinstal di lingkungan ini)* |
| **Sistem Operasi** | Ubuntu — Linux kernel 7.0.0, x86_64, glibc 2.43 |

> **Catatan penting**: Karena XGBoost versi 3.x, parameter `early_stopping_rounds` dimasukkan ke dalam konstruktor `XGBClassifier(...)`, bukan ke `.fit()`. Ini berbeda dari XGBoost < 3.x yang meletakkannya di `.fit()`. Kode `model-train-v2.py` sudah menangani kedua kondisi via blok `if XGBOOST_MAJOR >= 3`.

---

## No. 9 — Hasil Proses Pelatihan

| Parameter / Metrik Pelatihan | Nilai |
| :--- | :--- |
| `scale_pos_weight` | **0,8137** |
| Iterasi terbaik (`best_iteration`) | **733** (dari 1.000 estimators) |
| Threshold terpilih | **0,9529** (strategi: F1-Max pada validasi set) |
| Waktu pelatihan | *tidak dicatat di `model_meta.json`* |

> `best_iteration = 733` berarti *early stopping* terpicu pada iterasi ke-783 (733 + 50 *rounds*), menghentikan pelatihan sebelum mencapai 1.000 estimators penuh. Ini menunjukkan model mencapai konvergensi yang baik.

---

## No. 10 — Hasil Validasi dan Pengujian

### Validasi Set (13.164 sampel)

| Metrik | Nilai |
| :--- | :--- |
| TN | 5.904 |
| FP | 2 |
| FN | 9 |
| TP | 7.249 |
| **Accuracy** | **99,92%** |
| **Precision** | **99,97%** |
| **Recall (TPR)** | **99,88%** |
| **F1-Score** | **99,92%** |
| **ROC-AUC** | **99,9995%** |
| *Average Precision* | 99,9926% |
| FPR | 0,034% |

### Test Set (13.165 sampel)

| Metrik | Nilai |
| :--- | :--- |
| TN | 5.897 |
| FP | 9 |
| FN | 7 |
| TP | 7.252 |
| **Accuracy** | **99,88%** |
| **Precision** | **99,88%** |
| **Recall (TPR)** | **99,90%** |
| **F1-Score** | **99,89%** |
| **ROC-AUC** | **99,9637%** |
| *Average Precision* | 99,9422% |
| FPR | 0,152% |

> Semua angka di atas bersumber langsung dari `model_meta.json` bagian `"metrics"`.

---

## No. 11 — Daftar 30 Fitur Terpenting

Diambil dari `model_meta.json` bagian `"top_features"` (berdasarkan `feature_importances_` XGBoost):

| Rank | Fitur | Importance |
| :---: | :--- | ---: |
| 1 | `sc ` | 0,09393 |
| 2 | `http` | 0,07308 |
| 3 | `:/` | 0,04765 |
| 4 | `))` | 0,03857 |
| 5 | `ce` | 0,03460 |
| 6 | `//` | 0,03424 |
| 7 | ` 5` | 0,03326 |
| 8 | `0 1` | 0,02929 |
| 9 | `sc` | 0,02555 |
| 10 | `://` | 0,02526 |
| 11 | `1` | 0,02466 |
| 12 | `or` | 0,01833 |
| 13 | `.com` | 0,01767 |
| 14 | `1c` | 0,01751 |
| 15 | `0 ` | 0,01544 |
| 16 | `selec` | 0,01467 |
| 17 | `24` | 0,01333 |
| 18 | ` 2` | 0,01215 |
| 19 | ` 1` | 0,01179 |
| 20 | `ne` | 0,01144 |
| 21 | ` 1 ` | 0,01102 |
| 22 | ` whe` | 0,01090 |
| 23 | `) ` | 0,01073 |
| 24 | ` p` | 0,01050 |
| 25 | `top` | 0,01035 |
| 26 | `htt` | 0,01033 |
| 27 | `elect` | 0,00984 |
| 28 | ` or ` | 0,00982 |
| 29 | `sele` | 0,00974 |
| 30 | `1 2` | 0,00967 |

> Sebagian besar fitur terpenting adalah **karakter n-gram** dari TF-IDF Char (bukan kata utuh), mencerminkan pola karakter khas SQL Injection seperti `selec`, `elect`, ` or `, `))`, `://`, dll. Ini membuktikan bahwa pendekatan *char n-gram* efektif menangkap pola obfuskasi SQL.

---

## No. 12 — Status Artefak Keluaran

Semua artefak **berhasil dibuat** dan tersimpan di direktori proyek:

| File | Status | Ukuran | Keterangan |
| :--- | :---: | ---: | :--- |
| `tfidf_vectorizer.pkl` | ✅ Ada | 1,5 MB | `word_vec` + `char_vec` (dual vectorizer v2) |
| `feature_selector.pkl` | ✅ Ada | 627 KB | `SelectKBest(chi2, k=20000)` yang sudah di-*fit* |
| `xgb_sqli_model.pkl` | ✅ Ada | 996 KB | Model XGBoost (`best_iteration=733`) |
| `model_meta.json` | ✅ Ada | 5,8 KB | Metadata: threshold, metrik, config, top_features |

> File `.pkl` dan `model_meta.json` masuk dalam `.gitignore` sehingga tidak di-commit ke repositori, namun tersedia secara lokal.

---

## No. 13 — Kode Inferensi / Deployment Model

Kode inferensi sudah tersedia di file **`model_ML_run.py`** — komponen inti IPS yang berjalan secara *inline* via `NetfilterQueue`. Alur inferensinya:

```
[Paket HTTP masuk via NFQUEUE]
        ↓
Ekstrak payload dari URI / body HTTP
        ↓
preprocess_texts() — strip_bias, URL decode (maks 3 pass)
        ↓
build_features():
  ├── word_vec.transform()             → TF-IDF word n-gram  (maks 20.000 fitur)
  ├── char_vec.transform()             → TF-IDF char n-gram  (maks 20.000 fitur)
  └── extract_sql_keyword_features()   → 67 fitur biner SQL
        ↓
sp.hstack([X_word, X_char, X_kw])   → matriks hingga 40.067 fitur
        ↓
selector.transform()                 → seleksi ke 20.000 fitur (SelectKBest chi2)
        ↓
model.predict_proba()                → probabilitas [0.0 .. 1.0]
        ↓
proba >= threshold (0,9529)?
  ├── YA  → label "attack"  → paket di-DROP  (NFQUEUE verdict: DROP)
  └── TIDAK → label "benign" → paket diteruskan (NFQUEUE verdict: ACCEPT)
```

File `model_ML_run.py` memuat artefak dari:
- `tfidf_vectorizer.pkl` → `word_vec` + `char_vec`
- `feature_selector.pkl` → `selector`
- `xgb_sqli_model.pkl` → `model`
- `model_meta.json` → `threshold` (0,9529)

---

*File ini dibuat otomatis dari analisis artefak proyek — terakhir diperbarui: 2026-07-12*
