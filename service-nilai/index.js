const express = require('express');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
app.use(express.json());

// Hubungkan ke database SQLite bersama[cite: 2]
const dbPath = path.join(__dirname, '../database/zero_trust.db');
const db = new Database(dbPath);

const JWT_SECRET = 'rahasia_jwt_super_aman'; // Harus sama dengan di Gateway
const GATEWAY_SECRET = 'rahasia_gateway_123'; // Harus sama dengan di Gateway

// --- MIDDLEWARE ZERO TRUST (ASSUME BREACH) ---
const verifyZeroTrust = (req, res, next) => {
    // 1. Tolak akses langsung jika tidak ada secret dari Gateway[cite: 2]
    if (req.headers['x-gateway-secret'] !== GATEWAY_SECRET) {
        return res.status(403).json({ error: 'Akses langsung ke service ditolak. Gunakan Gateway.' });
    }

    // 2. Verifikasi ulang token JWT (Tanda tangan dan masa berlaku)[cite: 2]
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Token diperlukan' });
    
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Simpan data user (sub, role) ke request
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Token tidak valid di level service' });
    }
};

// Terapkan perlindungan Zero Trust ke semua route di service ini
app.use(verifyZeroTrust);

// --- ENDPOINT GET /nilai ---
app.get('/nilai', (req, res) => {
    const userId = req.user.sub;
    const role = req.user.role;

    try {
        if (role === 'mahasiswa') {
            // Mahasiswa hanya bisa melihat nilainya sendiri[cite: 2]
            const nilai = db.prepare(`
                SELECT n.id, k.nama_mk, n.nilai, n.is_final 
                FROM nilai n 
                JOIN kelas k ON n.kelas_id = k.id 
                WHERE n.mahasiswa_id = ?
            `).all(userId);
            return res.json({ data: nilai });
            
        } else if (role === 'dosen') {
            // Dosen hanya bisa melihat nilai dari kelas yang diampunya[cite: 2]
            const nilai = db.prepare(`
                SELECT n.id, n.mahasiswa_id, k.nama_mk, n.nilai, n.is_final 
                FROM nilai n 
                JOIN kelas k ON n.kelas_id = k.id 
                WHERE k.dosen_id = ?
            `).all(userId);
            return res.json({ data: nilai });
            
        } else {
            return res.status(403).json({ error: 'Role Anda tidak memiliki akses ke data nilai' });
        }
    } catch (error) {
        return res.status(500).json({ error: 'Terjadi kesalahan pada database' });
    }
});

// PUT /nilai/:id - Dosen mengupdate nilai (Gateway sudah mengecek jam akses)[cite: 2]
app.put('/nilai/:id', (req, res) => {
    const { id } = req.params;
    const { nilai } = req.body;
    
    if (req.user.role !== 'dosen') return res.status(403).json({ error: 'Hanya dosen' });

    // Validasi kepemilikan kelas & status final
    const dataNilai = db.prepare(`SELECT k.dosen_id, n.is_final FROM nilai n JOIN kelas k ON n.kelas_id = k.id WHERE n.id = ?`).get(id);
    
    if (!dataNilai) return res.status(404).json({ error: 'Data nilai tidak ditemukan' });
    if (dataNilai.dosen_id !== req.user.sub) return res.status(403).json({ error: 'Bukan kelas yang Anda ampu' });
    if (dataNilai.is_final) return res.status(403).json({ error: 'Nilai sudah final, tidak bisa diubah' });

    db.prepare('UPDATE nilai SET nilai = ? WHERE id = ?').run(nilai, id);
    res.json({ message: 'Nilai berhasil diupdate' });
});

// POST /kelas/:id/finalisasi - Dosen memfinalisasi dan memanggil Gateway[cite: 3]
app.post('/kelas/:id/finalisasi', async (req, res) => {
    if (req.user.role !== 'dosen') return res.status(403).json({ error: 'Hanya dosen' });

    const kelas = db.prepare('SELECT dosen_id FROM kelas WHERE id = ?').get(req.params.id);
    if (!kelas || kelas.dosen_id !== req.user.sub) return res.status(403).json({ error: 'Bukan kelas Anda' });

    // Tandai nilai sebagai final
    db.prepare('UPDATE nilai SET is_final = 1 WHERE kelas_id = ?').run(req.params.id);

    try {
        // 1. Minta Service Token ke API Gateway[cite: 2, 3]
        const authRes = await fetch('http://localhost:3000/auth/service', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ clientId: 'service-nilai', clientSecret: 'rahasia-service-nilai' })
        });
        const authData = await authRes.json();

        // 2. Panggil Service Transkrip MELEWATI Gateway menggunakan token tersebut[cite: 3]
        const syncRes = await fetch('http://localhost:3000/transkrip/sinkron', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authData.serviceToken}`
            },
            body: JSON.stringify({ kelas_id: req.params.id })
        });
        const syncData = await syncRes.json();

        res.json({ message: 'Finalisasi berhasil', sinkronisasi: syncData });
    } catch (error) {
        res.status(500).json({ error: 'Gagal komunikasi antar service melalui Gateway' });
    }
});

app.listen(3001, () => {
    console.log('Service Nilai berjalan di port 3001');
});