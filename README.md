# 🗳️ E-Voting Berbasis Infrastruktur Kunci Publik (PKI)

> Proyek skripsi ini mengimplementasikan sistem pemilihan umum elektronik dengan pendekatan kriptografi asimetris (RSA), tanda tangan digital, dan fungsi hash SHA-256, demi menjamin kerahasiaan, integritas, otentikasi, dan non-repudiasi suara pemilih.

---

## 📌 Fitur Utama

- ✅ Registrasi pemilih dengan pembangkitan pasangan kunci RSA
- 🔐 Enkripsi suara dengan RSA 2048-bit
- ✍️ Tanda tangan digital menggunakan SHA-256 dan kunci privat pemilih
- 📩 Verifikasi dan pengiriman suara via JSON ke server backend
- 🔓 Dekripsi dan validasi suara di server petugas sebelum dihitung
- 🧾 Data dikemas dalam format terenkripsi dan diverifikasi integritasnya

---

## 🧠 Arsitektur Sistem

```mermaid
graph TD
    A[Client (Browser)] -->|Registrasi| B[Flask (App Voter)]
    B -->|Public Key| C[Java - Authentication Server]
    B -->|Encrypted Vote| D[Java - Voting Server]
    D -->|Decrypted Vote| E[Java - Tabulation Server]
    E --> F[Database Suara]
```

**Frontend (Flask)**
- `app_voter` → port 5000  
- `app_officer` → port 5001  
- `app_admin` → port 5002  

**Backend (Java Socket Server)**
- `AuthenticationServer` → port 8080  
- `VotingServer` → port 8081  
- `TabulationServer` → port 8082  

---

## 🔐 Teknologi Kriptografi

| Komponen            | Algoritma       | Fungsi                                         |
|---------------------|------------------|------------------------------------------------|
| Kunci Publik/Privat | RSA 2048-bit     | Enkripsi & Dekripsi suara                      |
| Hashing             | SHA-256          | Menjamin integritas suara                     |
| Digital Signature   | RSA + SHA-256    | Autentikasi & Non-repudiasi                   |

---

## 💻 Cara Menjalankan Sistem

### 🧪 1. Jalankan Backend (Java)

```bash
cd src/backend
javac Main.java
java Main
```

### 🧪 2. Jalankan Frontend (Flask)

```bash
cd src/frontend/app_voter
python app_voter.py
```

> ⚠️ Pastikan `Flask`, `cryptography`, dan `requests` sudah terinstal.

---

## 🔎 Alur Singkat Proses Voting

1. Pemilih mengisi form registrasi → RSA Keypair terbentuk di browser
2. Public key dikirim ke server → private key disimpan oleh pemilih
3. Pemilih login menggunakan private key → sistem memverifikasi signature
4. Pemilih memilih kandidat → data di-hash dan dienkripsi
5. Vote terkirim ke server → didekripsi dan dihitung jika valid

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
- SHA-256, RSA (PyCA & BouncyCastle)
- Wireshark (untuk analisis jaringan)
- VirtualBox (uji coba 2 VM dalam jaringan host-only)

---
