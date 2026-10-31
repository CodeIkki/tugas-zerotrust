const Database = require('better-sqlite3');
const db = new Database('./database/zero_trust.db');

// Tabel Users dan Devices
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT
    );
    CREATE TABLE IF NOT EXISTS devices (
        user_id INTEGER,
        device_id TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
`);

// Tabel Refresh Tokens
db.exec(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        expires_at DATETIME
    );
`);

// Tabel Data Akademik
db.exec(`
    CREATE TABLE IF NOT EXISTS kelas (
        id INTEGER PRIMARY KEY,
        dosen_id INTEGER,
        nama_mk TEXT,
        FOREIGN KEY(dosen_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS nilai (
        id INTEGER PRIMARY KEY,
        mahasiswa_id INTEGER,
        kelas_id INTEGER,
        nilai TEXT,
        is_final BOOLEAN DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS transkrip (
        mahasiswa_id INTEGER PRIMARY KEY,
        data_transkrip TEXT
    );
`);

// Tabel Audit Log
db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        waktu TEXT,
        subjek TEXT,
        endpoint TEXT,
        device TEXT,
        hasil TEXT,
        alasan TEXT
    );
`);

// Data Users
const insertUser = db.prepare('INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)');
const insertDevice = db.prepare('INSERT INTO devices (user_id, device_id) VALUES (?, ?)');
const insertKelas = db.prepare('INSERT INTO kelas (id, dosen_id, nama_mk) VALUES (?, ?, ?)');

try {
    db.exec('BEGIN TRANSACTION');
    
    // 1 Admin[cite: 3]
    insertUser.run(1, 'admin1', 'pass123', 'admin');
    insertDevice.run(1, 'device-admin-1');

    // 2 Dosen[cite: 3]
    insertUser.run(2, 'dosen1', 'pass123', 'dosen');
    insertDevice.run(2, 'device-dosen-1');
    insertUser.run(3, 'dosen2', 'pass123', 'dosen');
    insertDevice.run(3, 'device-dosen-2');

    // 3 Mahasiswa[cite: 3]
    insertUser.run(4, 'mhs1', 'pass123', 'mahasiswa');
    insertDevice.run(4, 'device-mhs-1');
    insertUser.run(5, 'mhs2', 'pass123', 'mahasiswa');
    insertDevice.run(5, 'device-mhs-2');
    insertUser.run(6, 'mhs3', 'pass123', 'mahasiswa');
    insertDevice.run(6, 'device-mhs-3');

    // 2 Kelas diampu dosen berbeda[cite: 3]
    insertKelas.run(1, 2, 'Keamanan Informasi'); // Diampu dosen 1
    insertKelas.run(2, 3, 'Komputasi Paralel dan Terdistribusi');    // Diampu dosen 2

    db.exec('COMMIT');
    console.log("Database dan data awal (seed) berhasil dibuat!");
} catch (error) {
    db.exec('ROLLBACK');
    console.error("Gagal melakukan seeding:", error);
}