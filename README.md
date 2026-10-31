# Tugas Praktikum Individu: Zero Trust Security

Repositori ini berisi implementasi arsitektur **Zero Trust Security** pada level aplikasi menggunakan Node.js dan Express. Sistem ini bertindak sebagai Sistem Nilai yang mengimplementasikan API Gateway sebagai Policy Enforcement Point (PEP), memverifikasi setiap *request* (termasuk konteks perangkat dan waktu), dan menerapkan prinsip *Assume Breach* pada komunikasi antar-layanan.

## Prasyarat
- Node.js (versi 22+ direkomendasikan)
- npm (Node Package Manager)

## Instalasi
1. Clone atau ekstrak repositori ini ke komputer Anda.
2. Buka terminal di dalam folder utama proyek (`tugas-zerotrust`).
3. Jalankan perintah instalasi dependensi:
   npm init -y
   npm install express jsonwebtoken http-proxy-middleware better-sqlite3
4. Buat dan isi database awal (seed) dengan menjalankan perintah:
   node database/setup.js

## Cara Menjalankan Aplikasi
Sistem ini terdiri dari tiga layanan terpisah. Anda perlu membuka **tiga terminal berbeda** dan menjalankan perintah berikut di masing-masing terminal:

- **Terminal 1 (API Gateway - Port 3000):**
  node gateway/index.js
- **Terminal 2 (Service Nilai - Port 3001):**
  node service-nilai/index.js
- **Terminal 3 (Service Transkrip - Port 3002):**
  node service-transkrip/index.js

## Data Awal (Akun & Device ID)
Sistem memvalidasi kredensial login beserta **Device ID** yang terdaftar. Saat melakukan request melalui Postman, pastikan menyisipkan header `X-Device-ID` yang sesuai dengan akun di bawah ini:

| Role      | Username | Password | X-Device-ID      |
|-----------|----------|----------|------------------|
| Admin     | admin1   | pass123  | device-admin-1   |
| Dosen     | dosen1   | pass123  | device-dosen-1   |
| Dosen     | dosen2   | pass123  | device-dosen-2   |
| Mahasiswa | mhs1     | pass123  | device-mhs-1     |
| Mahasiswa | mhs2     | pass123  | device-mhs-2     |
| Mahasiswa | mhs3     | pass123  | device-mhs-3     |

## 📌 Endpoint Utama (via API Gateway port 3000)
- `POST /auth/login` : Autentikasi dan mendapatkan Access & Refresh Token.
- `POST /auth/refresh`: Memperbarui Access Token.
- `POST /auth/logout` : Mencabut Refresh Token.
- `GET /nilai`        : Melihat nilai (Sesuai role).
- `PUT /nilai/:id`    : (Dosen) Update nilai (diizinkan jam 07.00 - 21.00).
- `POST /kelas/:id/finalisasi` : (Dosen) Finalisasi kelas dan memicu sinkronisasi antar-service.