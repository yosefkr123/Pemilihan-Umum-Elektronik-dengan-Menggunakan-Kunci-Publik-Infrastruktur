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

## 📊 Arsitektur Sistem (Diagram Sederhana)

```mermaid
flowchart TD
    subgraph Client
        A[Browser (Pemilih)]
    end

    subgraph Frontend
        B[Flask - app_voter\nPort 5000]
        C[Flask - app_officer\nPort 5001]
        D[Flask - app_admin\nPort 5002]
    end

    subgraph Backend
        E[Authentication Server\nPort 8080]
        F[Voting Server\nPort 8081]
        G[Tabulasi Server\nPort 8082]
    end

    A --> B --> E
    C <--> F --> G


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
