# 🗳️ E-Voting Berbasis Infrastruktur Kunci Publik (PKI)

> Proyek ini mengimplementasikan sistem pemilihan umum elektronik dengan pendekatan kriptografi asimetris (RSA), tanda tangan digital, dan fungsi hash SHA-256, demi menjamin kerahasiaan, integritas, otentikasi, dan non-repudiasi suara pemilih.

---

## 📁 Struktur Folder

```
Pemilihan-Umum-Elektronik-dengan-Menggunakan-Kunci-Publik-Infrastruktur/
├── src/
│   ├── Backend/
│   │   ├── AuthenticationServer.java
│   │   ├── VotingServer.java
│   │   └── TabulasiServer.java
│   └── Frontend/
│       ├── app_voter.py
│       ├── app_officer.py
│       └── app_admin.py
```

---

## 📌 Fitur Utama

- ✅ Registrasi pemilih dengan pembangkitan kunci RSA di browser
- 🔐 Enkripsi suara dengan RSA 2048-bit
- ✍️ Tanda tangan digital berbasis SHA-256
- 📩 Pengiriman suara terenkripsi dalam format JSON
- 🔓 Dekripsi suara oleh petugas dan verifikasi integritas
- 📊 Penghitungan suara hanya untuk suara valid

---

## 📊 Arsitektur Sistem 

Struktur komunikasi antara frontend dan backend pada sistem ini terdiri dari beberapa komponen utama yang berjalan pada port yang berbeda:

**Client Side (Frontend – Flask)**
- `app_voter.py`   → `Port 5000`
  → Menyediakan antarmuka untuk pemilih melakukan registrasi, login, dan pemungutan suara.

- `app_officer.py` → `Port 5001`
  → Digunakan oleh petugas untuk menerima dan memproses suara terenkripsi.

- `app_admin.py`   → `Port 5002`
  → Digunakan oleh admin untuk melihat hasil tabulasi suara dan manajemen data.

**Server Side (Backend – Java Socket Server)**
- `Authentication Server` → `Port 8080`
  → Menerima data registrasi dan proses verifikasi identitas pemilih.

- `Voting Server`         → `Port 8081`
  → Menerima suara terenkripsi dan menyimpan suara yang telah tervalidasi.

- `Tabulasi Server`       → `Port 8082`
  → Menghitung dan menyajikan hasil akhir pemungutan suara berdasarkan suara yang sah.

Komunikasi antar Komponen
- Pemilih mengakses aplikasi via browser ke app_voter.py
- Flask frontend mengirim data melalui HTTP (format JSON) ke server Java

 

---

## 🔐 Teknologi Kriptografi

| Komponen            | Algoritma       | Fungsi                                         |
|---------------------|------------------|------------------------------------------------|
| Kunci Publik/Privat | RSA 2048-bit     | Enkripsi & Dekripsi suara                      |
| Hashing             | SHA-256          | Menjamin integritas suara                     |
| Digital Signature   | RSA + SHA-256    | Autentikasi & Non-repudiasi                   |

---

## 💻 Cara Menjalankan Sistem

### 🧪 1. Clone Repository

```bash
git clone https://github.com/username/Pemilihan-Umum-Elektronik-dengan-Menggunakan-Kunci-Publik-Infrastruktur.git
cd Pemilihan-Umum-Elektronik-dengan-Menggunakan-Kunci-Publik-Infrastruktur/src
```

### 🧪 2. Jalankan Backend (Java)

```bash
cd Backend
javac AuthenticationServer.java VotingServer.java TabulasiServer.java
java AuthenticationServer
java VotingServer
java TabulasiServer
```

### 🧪 3. Jalankan Frontend (Flask)

```bash
cd ../Frontend

# Di terminal terpisah untuk setiap app
python app_voter.py     # port 5000
python app_officer.py   # port 5001
python app_admin.py     # port 5002
```

> ⚠️ Pastikan `Flask`, `cryptography`, dan `requests` telah terinstal.

---

## 🔄 Alur Proses Voting

1. **Registrasi:** Pemilih membuat pasangan kunci RSA langsung di browser.
2. **Verifikasi:** Tanda tangan digital dibuat dengan private key, diverifikasi oleh server.
3. **Voting:** Suara di-hash dan dienkripsi, dikirim sebagai JSON ke server.
4. **Dekripsi & Validasi:** Petugas mendekripsi suara dan memverifikasi integritas.
5. **Tabulasi:** Hanya suara sah yang dihitung dan disimpan.

---

## 📈 Hasil Pengujian

- ✅ Komunikasi terenkripsi (RSA & HTTPS)
- ✅ Payload JSON tidak bocor data sensitif
- ✅ Validasi signature 100% akurat
- ✅ Integritas suara dijaga via hash

---

## 📚 Teknologi yang Digunakan

- Python (Flask, Cryptography)
- Java (Socket Server)
- SHA-256, RSA
- Wireshark (untuk analisis jaringan)
- VirtualBox (uji coba 2 VM dalam jaringan host-only)

---
