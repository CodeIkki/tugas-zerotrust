// gateway/index.js
const express = require('express');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
app.use(express.json());

// Hubungkan ke database yang sudah dibuat
const dbPath = path.join(__dirname, '../database/zero_trust.db');
const db = new Database(dbPath);

const JWT_SECRET = 'rahasia_jwt_super_aman';
const GATEWAY_SECRET = 'rahasia_gateway_123';

// Fungsi untuk mencatat Audit Log[cite: 3]
const logAudit = (subjek, endpoint, device, hasil, alasan) => {
    db.prepare(`INSERT INTO audit_logs (waktu, subjek, endpoint, device, hasil, alasan) 
                VALUES (?, ?, ?, ?, ?, ?)`).run(new Date().toISOString(), subjek, endpoint, device, hasil, alasan);
};

app.post('/auth/login', (req, res) => {
    const { username, password } = req.body;
    const deviceId = req.header('X-Device-ID');
    const endpoint = '/auth/login';

    // 1. Validasi input dasar
    if (!username || !password || !deviceId) {
        logAudit('Guest', endpoint, deviceId || 'Unknown', 'deny', 'Missing credentials or X-Device-ID');
        return res.status(400).json({ error: 'Username, password, dan header X-Device-ID wajib diisi' });
    }

    // 2. Verifikasi Kredensial di Database
    const user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?').get(username, password);
    if (!user) {
        logAudit(username, endpoint, deviceId, 'deny', 'Kredensial tidak valid');
        return res.status(401).json({ error: 'Username atau password salah' });
    }

    // 3. Verifikasi Konteks: Device Terdaftar[cite: 3]
    const validDevice = db.prepare('SELECT * FROM devices WHERE user_id = ? AND device_id = ?').get(user.id, deviceId);
    if (!validDevice) {
        logAudit(user.id, endpoint, deviceId, 'deny', 'Device tidak terdaftar');
        return res.status(403).json({ error: 'Device tidak terdaftar untuk user ini' });
    }

    // 4. Generate Access Token (JWT berlaku 10 menit, berisi sub dan role)[cite: 2]
    const accessToken = jwt.sign(
        { sub: user.id, role: user.role }, 
        JWT_SECRET, 
        { expiresIn: '10m' }
    );
    
    // 5. Generate Refresh Token (berlaku 1 hari)[cite: 2]
    const refreshToken = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '1d' });
    
    // Simpan refresh token ke database agar dapat dicabut (logout)[cite: 2]
    db.prepare(`INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+1 day'))`)
      .run(refreshToken, user.id);

    // 6. Catat Audit Log Berhasil[cite: 3]
    logAudit(user.id, endpoint, deviceId, 'allow', 'Login berhasil');

    res.json({
        message: 'Login berhasil',
        accessToken,
        refreshToken
    });
});

// POST /auth/refresh - Mendapatkan access token baru[cite: 2]
app.post('/auth/refresh', (req, res) => {
    const { refreshToken } = req.body;
    const deviceId = req.header('X-Device-ID');
    const endpoint = '/auth/refresh';

    if (!refreshToken) return res.status(401).json({ error: 'Refresh token diperlukan' });

    // Cek apakah token ada di database dan belum kedaluwarsa
    const tokenRecord = db.prepare(`SELECT * FROM refresh_tokens WHERE token = ? AND expires_at > datetime('now')`).get(refreshToken);
    
    if (!tokenRecord) {
        logAudit('Unknown', endpoint, deviceId || 'Unknown', 'deny', 'Refresh token tidak valid atau kedaluwarsa');
        return res.status(403).json({ error: 'Refresh token tidak valid' });
    }

    try {
        const decoded = jwt.verify(refreshToken, JWT_SECRET);
        const user = db.prepare('SELECT role FROM users WHERE id = ?').get(decoded.sub);
        
        // Terbitkan access token baru (10 menit)[cite: 2]
        const newAccessToken = jwt.sign({ sub: decoded.sub, role: user.role }, JWT_SECRET, { expiresIn: '10m' });
        
        logAudit(decoded.sub, endpoint, deviceId, 'allow', 'Access token diperbarui');
        res.json({ accessToken: newAccessToken });
    } catch (err) {
        return res.status(403).json({ error: 'Token kedaluwarsa' });
    }
});

// POST /auth/logout - Mencabut refresh token[cite: 2]
app.post('/auth/logout', (req, res) => {
    const { refreshToken } = req.body;
    if (refreshToken) {
        db.prepare('DELETE FROM refresh_tokens WHERE token = ?').run(refreshToken);
    }
    res.json({ message: 'Logout berhasil, token dicabut' });
});

const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware'); 

// --- ENDPOINT TOKEN SERVICE ---
// Digunakan nanti oleh Service Nilai untuk mendapatkan token sebelum memanggil Service Transkrip[cite: 2, 3]
app.post('/auth/service', (req, res) => {
    const { clientId, clientSecret } = req.body;
    const endpoint = '/auth/service';
    const deviceId = 'Service-Internal';

    if (clientId === 'service-nilai' && clientSecret === 'rahasia-service-nilai') {
        const serviceToken = jwt.sign({ sub: clientId, role: 'service' }, JWT_SECRET, { expiresIn: '5m' }); // Berlaku 5 menit[cite: 2]
        logAudit(clientId, endpoint, deviceId, 'allow', 'Token service diterbitkan');
        return res.json({ serviceToken });
    }
    
    logAudit(clientId || 'Unknown', endpoint, deviceId, 'deny', 'Kredensial service tidak valid');
    return res.status(401).json({ error: 'Client ID atau Secret salah' });
});

// --- POLICY ENGINE (MIDDLEWARE) ---
// Memutuskan allow/deny berdasarkan aturan Zero Trust[cite: 2]
const verifyPolicy = (req, res, next) => {
    const endpoint = req.originalUrl;
    const deviceId = req.header('X-Device-ID');
    const authHeader = req.header('Authorization');

    // 1. Verifikasi keberadaan token[cite: 2]
    if (!authHeader) {
        logAudit('Guest', endpoint, deviceId || 'Unknown', 'deny', 'Missing Token');
        return res.status(401).json({ error: 'Akses ditolak: Token tidak ditemukan' });
    }

    const token = authHeader.split(' ')[1];

    try {
        // 2. Verifikasi validitas JWT (tanda tangan dan masa berlaku)[cite: 2]
        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.sub;
        const role = decoded.role;

        // 3. Verifikasi Konteks: Device Terdaftar (Kecuali token khusus service)[cite: 3]
        if (role !== 'service') {
            const validDevice = db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?').get(userId, deviceId);
            if (!validDevice) {
                logAudit(userId, endpoint, deviceId, 'deny', 'Device tidak terdaftar');
                return res.status(403).json({ error: 'Device tidak terdaftar untuk user ini' });
            }
        }

        // 4. Verifikasi Konteks: Jam Akses (07.00 - 21.00)[cite: 3]
        // Berlaku untuk modifikasi nilai dan finalisasi
        if ((req.method === 'PUT' && endpoint.startsWith('/nilai')) || endpoint.includes('/finalisasi')) {
            const currentHour = new Date().getHours();
            if (currentHour < 7 || currentHour >= 21) {
                logAudit(userId, endpoint, deviceId, 'deny', 'Di luar jam akses');
                return res.status(403).json({ error: 'Perubahan nilai hanya diizinkan pukul 07.00 - 21.00' });
            }
        }

        // Jika lolos semua kebijakan
        logAudit(userId, endpoint, deviceId, 'allow', 'Policy Gateway Passed');
        req.user = decoded; // Menyisipkan data hasil decode
        next(); // Lanjutkan ke proxy
    } catch (err) {
        logAudit('Unknown', endpoint, deviceId || 'Unknown', 'deny', 'Token tidak valid/kedaluwarsa');
        return res.status(401).json({ error: 'Token tidak valid atau sudah kedaluwarsa' });
    }
};

// --- ROUTING / PROXY KE SERVICE INTERNAL ---
// Menambahkan X-Gateway-Secret saat meneruskan request[cite: 2]
const proxyOptions = {
    changeOrigin: true,
    pathRewrite: (path, req) => req.originalUrl,
    on: {proxyReq: (proxyReq, req, res) => {
            proxyReq.setHeader('X-Gateway-Secret', GATEWAY_SECRET);
            if (req.body && Object.keys(req.body).length > 0) {
                fixRequestBody(proxyReq, req);
            }
        }
    }
};

// Route ke Service Nilai (Berjalan di Port 3001)[cite: 1, 2]
app.use('/nilai', verifyPolicy, createProxyMiddleware({ ...proxyOptions, target: 'http://localhost:3001' }));
app.use('/kelas', verifyPolicy, createProxyMiddleware({ ...proxyOptions, target: 'http://localhost:3001' }));

// Route ke Service Transkrip (Berjalan di Port 3002)[cite: 1, 2]
app.use('/transkrip', verifyPolicy, createProxyMiddleware({ ...proxyOptions, target: 'http://localhost:3002' }));

app.listen(3000, () => {
    console.log('API Gateway (PEP) berjalan di port 3000');
});