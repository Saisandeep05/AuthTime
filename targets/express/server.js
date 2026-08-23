/**
 * Express.js Reference Authorization Target for AuthTime.
 * Binds strictly to 127.0.0.1.
 */

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const JWT_SECRET = 'authtime-secret-key-32-bytes-long!';
const HOST = '127.0.0.1';
const PORT = 8001;

let userRoles = {
    'admin1': 'Admin',
    'user1': 'User'
};

let authCache = {};
let auditEvents = [];

// Middleware: Validate Local Loopback
app.use((req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress;
    if (!ip.includes('127.0.0.1') && !ip.includes('::1') && !ip.includes('localhost')) {
        return res.status(403).json({ error: "Access Restricted to 127.0.0.1" });
    }
    next();
});

// Login
app.post('/auth/login', (req, res) => {
    const userId = req.body.user_id || 'admin1';
    const role = userRoles[userId] || 'User';
    const token = jwt.sign({ sub: userId, role: role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ access_token: token, token_type: 'bearer' });
});

// Protected Resource
app.get('/admin/users', (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ detail: "Missing Token" });
    
    const token = authHeader.split(' ')[1];
    let decoded;
    try {
        decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        return res.status(401).json({ detail: "Invalid Token" });
    }

    const userId = decoded.sub;
    const now = Date.now() / 1000;
    
    let role = userRoles[userId];
    if (authCache[userId] && authCache[userId].expires_at > now) {
        role = authCache[userId].role;
    }

    auditEvents.push({
        timestamp: now,
        user_id: userId,
        action: 'GET /admin/users',
        decision: role === 'Admin' ? 'ALLOW' : 'DENY'
    });

    if (role !== 'Admin') {
        return res.status(403).json({ detail: "Permission Denied" });
    }

    res.json({ users: ['admin1', 'user1'], count: 2, target: "Express.js" });
});

// Fault Injection Controller
app.post('/faults/inject', (req, res) => {
    const { fault_type, user_id, new_role, cache_ttl_seconds } = req.body;
    const now = Date.now() / 1000;

    userRoles[user_id] = new_role;

    if (fault_type === 'stale_cache') {
        authCache[user_id] = {
            role: 'Admin',
            expires_at: now + (cache_ttl_seconds || 30)
        };
    }

    res.json({ status: "fault_injected", fault_type, user_id, new_role });
});

// Reset State
app.post('/faults/reset', (req, res) => {
    userRoles = { 'admin1': 'Admin', 'user1': 'User' };
    authCache = {};
    auditEvents = [];
    res.json({ status: "reset_complete" });
});

app.listen(PORT, HOST, () => {
    console.log(`[*] Express.js Auth Target running on http://${HOST}:${PORT}`);
});
