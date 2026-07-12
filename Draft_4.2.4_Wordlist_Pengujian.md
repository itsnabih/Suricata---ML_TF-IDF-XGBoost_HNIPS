## 4.2.4 Perumusan dan Pengumpulan Data Wordlist Pengujian

Pengujian sistem IPS memerlukan dua kelompok data *wordlist* yang berbeda peran dan sumbernya: **wordlist traffic normal** untuk mengukur *False Positive*, dan **wordlist payload serangan** untuk mengukur *Detection Rate*. Berikut adalah proses perumusan dan pembentukan keduanya.

---

### A. Wordlist Traffic Normal — `dvwa_wordlist.txt`

**Tujuan:** Mensimulasikan perilaku pengguna sah yang mengakses aplikasi DVWA secara normal, tanpa unsur injeksi apapun.

**Sumber data:** Direktori dan *endpoint* DVWA dikompilasi secara manual dengan metode enumerasi (*directory enumeration*) terhadap struktur aplikasi DVWA yang berjalan di Docker Container (`172.17.0.2:80`).

**Metode pembentukan:**

Semua *path* URL DVWA yang dapat diakses oleh pengguna terautentikasi dipetakan secara menyeluruh, mencakup empat kelompok:

1. **Halaman utama dan administratif** — seperti `/index.php`, `/login.php`, `/setup.php`, `/security.php`, `/phpinfo.php`, dan `/robots.txt`.
2. **Seluruh modul kerentanan DVWA beserta *source view*-nya** — mencakup 14 modul seperti `/vulnerabilities/sqli/`, `/vulnerabilities/brute/`, `/vulnerabilities/xss_r/`, `/vulnerabilities/fi/`, `/vulnerabilities/upload/`, `/vulnerabilities/xxe/`, dan lainnya. Setiap modul juga dipetakan hingga ke halaman kode sumbernya (`/source/low.php`, `medium.php`, `high.php`).
3. **File statis** (*CSS*, *JavaScript*, gambar) di direktori `/dvwa/css/`, `/dvwa/js/`, `/dvwa/images/`, dan direktori library eksternal `/external/`.
4. ***Edge case* ambiguitas** — *path* yang mengandung karakter yang secara sintaks menyerupai elemen SQL, namun secara semantik bukan serangan. Contohnya:
   - `/vulnerabilities/brute/?name=O'Connor` → mengandung tanda kutip tunggal (`'`), namun bukan injeksi.
   - `/setup.php/?article=union_jack` → mengandung kata `union`, namun merupakan nama artikel biasa.
   - `/vulnerabilities/sqli/?id=8&Submit=Submit` → parameter `id` berisi integer valid, bukan *payload*.

   Kasus-kasus ini sengaja dimasukkan untuk menguji apakah sistem IPS memiliki tingkat *False Positive* yang dapat diterima saat menghadapi input normal yang ambigu.

Daftar *path* yang telah terkompilasi kemudian **direplikasi sebanyak 3 kali** secara identik untuk mencapai volume total yang representatif terhadap *traffic* normal.

**Hasil akhir:** File [`dvwa_wordlist.txt`](file:///home/ubuntu/Documents/HNIPS_project/dvwa_wordlist.txt) — **700 entri URL** yang merepresentasikan *traffic* HTTP normal dari berbagai pola akses pengguna sah.

---

### B. Wordlist Payload Serangan — `sqli_payloads.txt`

**Tujuan:** Mensimulasikan serangan SQL Injection yang nyata, mencakup berbagai teknik dan tingkat obfuskasi yang umumnya digunakan penyerang.

#### B.1 — Sumber Asal: `OneListSqli.txt` & `sqli.txt` (Repo *OneListForAll*)

*Wordlist* serangan bersumber dari repositori publik **OneListForAll** — sebuah koleksi *payload* penetrasi yang dikurasi dari berbagai sumber komunitas keamanan siber. Dua file digunakan sebagai bahan mentah:

| File | Jumlah Baris | Deskripsi |
| :--- | :---: | :--- |
| `OneListSqli.txt` | 22.653 | Koleksi lengkap dari repositori *OneListForAll* |
| `sqli.txt` | 32.684 | Superset gabungan yang mencakup variasi lebih luas |

Kedua file ini merupakan kompilasi *payload* SQL Injection lintas teknik dan lintas DBMS (*MySQL, PostgreSQL, MSSQL Server, Oracle*), mencakup mulai dari *payload* dasar hingga teknik *obfuscation* tingkat lanjut.

#### B.2 — Proses Kurasi dengan `generate_wordlist.py`

Menggunakan seluruh ribuan *payload* secara langsung akan menghasilkan pengujian yang tidak efisien, redundan, dan tidak terstruktur. Oleh karena itu, dibuat skrip Python [`generate_wordlist.py`](file:///home/ubuntu/Documents/HNIPS_project/generate_wordlist.py) untuk melakukan **stratified sampling berbasis kategori teknik serangan**.

Proses kerja skrip ini adalah sebagai berikut:

**Langkah 1 — Klasifikasi Kategori via Regex**

Setiap baris *payload* dari `sqli.txt` diklasifikasikan ke dalam **13 kategori teknik serangan** menggunakan pencocokan ekspresi reguler (*regex*). Kategori ini sepenuhnya **diselaraskan dengan cakupan deteksi aturan Suricata** (`sqli_detection.rules`) yang berjalan sebagai lapisan pertama sistem IPS, sehingga terdapat konsistensi antara *payload* yang diuji dengan pola yang sesungguhnya dideteksi. Kategori dan pola pengenal yang digunakan adalah:

| No | Kategori Teknik Serangan | Pola Regex Pengenal | SID Suricata |
| :---: | :--- | :--- | :---: |
| 1 | Basic Quote & Comment | `'`, `"`, `--`, `#`, `/*` | 1000002–1000003 |
| 2 | Boolean-based Blind | `\b(and\|or)\b.{0,40}\b\d+=\d+\b` | 1000004–1000005 |
| 3 | Time-based Blind | `sleep\s*\(`, `pg_sleep\s*\(`, `waitfor\s+delay`, `benchmark\s*\(` | 1000006–1000009 |
| 4 | UNION-based | `union\s+(all\s+)?select` | 1000010–1000011 |
| 5 | Error-based | `extractvalue\s*\(`, `concat.*0x7e` | 1000012–1000013 |
| 6 | URL Encoded | `%27`, `%22`, `%2D%2D`, `%23`, `%2F%2A`, `%2A%2F` | 1000014 |
| 7 | Database Fingerprinting | `@@version`, `version()`, `@@servername` | 1000015–1000017 |
| 8 | ORDER BY Enumeration | `order\s+by\s+\d+` | 1000018 |
| 9 | Null Byte | `%00` | 1000019 |
| 10 | DB Function Calls | `current_user()`, `user()`, `session_user()`, `database()`, `schema()` | 1000020–1000021 |
| 11 | Hex Encoded | `0x[0-9a-f]{2,}` | 1000023 |
| 12 | File System Access | `load_file\s*\(` | 1000024 |
| 13 | SQLMap User-Agent *(suspended)* | `User-Agent: sqlmap` | ~~1000001~~ |

Klasifikasi bersifat **hierarkis** — setiap *payload* hanya masuk ke dalam satu kategori pertama yang cocok berdasarkan urutan prioritas di atas, sehingga tidak ada duplikasi antar kategori. Kategori ke-13 (*SQLMap User-Agent*) dinonaktifkan dalam aturan Suricata agar pengujian berfokus pada deteksi *payload*, bukan identifikasi alat — namun tetap dicantumkan di sini sebagai referensi kelengkapan cakupan rancangan aturan.

**Langkah 2 — Pengambilan Sampel (*Stratified Sampling*)**

Dari setiap *bucket* kategori, diambil sejumlah sampel yang telah ditentukan (*target*) menggunakan `random.sample()`. Distribusi target per kategori dirancang untuk mencerminkan proporsi teknik serangan yang realistis sekaligus memastikan seluruh 12 kategori deteksi aktif Suricata terwakili:

| No | Kategori Teknik | Hasil Aktual | Keterangan |
| :---: | :--- | :---: | :--- |
| 1 | Basic Quote & Comment | 118 | *Payload* dasar karakter kutip dan komentar SQL |
| 2 | Boolean-based Blind | 62 | Teknik inferensi berbasis respons `True/False` |
| 3 | Time-based Blind | 61 | Teknik *blind* berbasis penundaan waktu (`SLEEP`, `pg_sleep`, `WAITFOR`) |
| 4 | UNION-based | 61 | Teknik enumerasi kolom dan data via `UNION SELECT` |
| 5 | Error-based | 0 | Teknik eksploitasi pesan *error* DBMS — tidak tersedia di sumber |
| 6 | URL Encoded | 34 | *Payload* dengan obfuskasi *URL encoding* (`%27`, `%22`, dll.) |
| 7 | Database Fingerprinting | 16 | Enumerasi versi/identitas DBMS (`@@version`, `version()`, `@@SERVERNAME`) |
| 8 | ORDER BY Enumeration | 20 | Teknik pencarian jumlah kolom via `ORDER BY <angka>` |
| 9 | Null Byte | 19 | *Payload* terminasi string dengan `%00` untuk bypass filter |
| 10 | DB Function Calls | 2 | Pemanggilan fungsi informasi DB (`USER()`, `DATABASE()`, `SCHEMA()`) |
| 11 | Hex Encoded | 30 | *Payload* dengan konversi nilai ke heksadesimal (`0x...`) |
| 12 | File System Access | 0 | Upaya pembacaan file server via `LOAD_FILE()` — tidak tersedia di sumber |
| | **Total Payload Efektif** | **423** | *(dari 449 baris file; 26 baris sisanya adalah komentar penanda kategori `#`)* |

**Langkah 3 — Penyimpanan**

Seluruh *payload* terpilih digabungkan dan disimpan ke file `sqli_payloads.txt`. File ini kemudian digunakan oleh skrip pengujian (`send_attack.sh`) sebagai sumber serangan yang dikirimkan secara berurutan ke target DVWA melalui `curl`.

**Hasil akhir:** File [`sqli_payloads.txt`](file:///home/ubuntu/Documents/HNIPS_project/sqli_payloads.txt) — **423 *payload* efektif** (449 baris total, termasuk 26 baris komentar penanda kategori) yang merepresentasikan serangan SQL Injection dengan **10 dari 12 teknik aktif** yang selaras dengan cakupan aturan Suricata, dikurasi dari lebih dari 32.000 *payload* sumber.

> **Catatan**: Dua kategori (*Error-based* dan *File System Access*) tidak memiliki representasi dalam *wordlist* ini karena keterbatasan ketersediaan *payload* spesifik di sumber `sqli.txt`. Meskipun demikian, kedua kategori tersebut tetap tercakup dalam aturan deteksi Suricata dan modul ML, sehingga tidak mempengaruhi kemampuan deteksi sistem secara keseluruhan.

---

### C. Ringkasan Komposisi Data Pengujian

| Aspek | Wordlist Normal (`dvwa_wordlist.txt`) | Wordlist Serangan (`sqli_payloads.txt`) |
| :--- | :---: | :---: |
| Sumber | Enumerasi direktori DVWA manual | Repo *OneListForAll* (`sqli.txt`, `OneListSqli.txt`) |
| Jumlah Entri | 700 URL | 423 *payload* efektif (449 baris total) |
| Tujuan dalam Pengujian | Mengukur *False Positive Rate* | Mengukur *Detection Rate* / *True Positive* |
| Metode Kurasi | Enumerasi manual + replikasi 3x | *Stratified sampling* via `generate_wordlist.py` |
| Cakupan | 14 modul DVWA + file statis + *edge case* | **13 kategori** teknik SQL Injection (12 aktif + 1 *suspended*), selaras penuh dengan aturan Suricata |

---

### D. Alur Pembentukan Data Wordlist (Diagram)

```
[Sumber 1: Repositori OneListForAll]
         |
         | sqli.txt (32.684 payload)
         | OneListSqli.txt (22.653 payload)
         v
[generate_wordlist.py]
    |-- Klasifikasi regex ke 13 kategori (selaras aturan Suricata)
    |-- Stratified sampling per kategori (12 kategori aktif)
    v
[sqli_payloads.txt]           [Enumerasi Direktori DVWA]
(449 payload serangan)                  |
         |                              v
         |                    [dvwa_wordlist.txt]
         |                    (700 URL normal)
         |                              |
         +------------------------------+
                         |
                         v
              [Pengujian IPS — send_attack.sh
               & send_normal.sh via curl]
                         |
                         v
              [Data Log → saved_logs/]
```
