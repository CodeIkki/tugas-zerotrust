// service-transkrip/index.js
const express = require('express');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
app.use(express.json());

const dbPath = path.join(__dirname, '../database/zero_trust.db');
const db = new Database(dbPath);

const JWT_SECRET = 'rahasia_jwt_super_aman';
const GATEWAY_SECRET = 'rahasia_gateway_123';

// --- MIDDLEWARE ZERO TRUST ---
const verifyZeroTrust = (req, res, next) => {
    if (req.headers['x-gateway-secret'] !== GATEWAY_SECRET) {
        return res.status(403).json({ error: 'Akses langsung ditolak' });
    }
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Token diperlukan' });
    
    try {
        const token = authHeader.split(' ')[1];
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Token tidak valid' });
    }
};

app.use(verifyZeroTrust);

// --- ENDPOINT GET /transkrip/:nim ---
// Mahasiswa: Hanya NIM sendiri. Admin: Semua NIM[cite: 3]
app.get('/transkrip/:nim', (req, res) => {
    const { nim } = req.params; // nim di sini kita samakan dengan id user/mahasiswa
    const userId = req.user.sub.toString();
    const role = req.user.role;

    if (role === 'mahasiswa' && userId !== nim) {
        return res.status(403).json({ error: 'Hanya bisa melihat transkrip sendiri' });
    }
    if (role !== 'mahasiswa' && role !== 'admin') {
        return res.status(403).json({ error: 'Role tidak diizinkan' });
    }

    const data = db.prepare('SELECT * FROM transkrip WHERE mahasiswa_id = ?').get(nim);
    res.json({ data: data || { catatan: "Belum ada transkrip" } });
});

// --- ENDPOINT SINKRONISASI ---
// Hanya boleh diakses oleh token service[cite: 3]
app.post('/transkrip/sinkron', (req, res) => {
    if (req.user.role !== 'service') {
        return res.status(403).json({ error: 'Hanya sistem internal yang bisa melakukan sinkronisasi' });
    }
    // Di aplikasi nyata, di sini akan ada query insert ke tabel transkrip
    res.json({ message: 'Sinkronisasi berhasil dilakukan dari Service Nilai' });
});

app.listen(3002, () => {
    console.log('Service Transkrip berjalan di port 3002');
});