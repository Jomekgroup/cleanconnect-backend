const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

// ============================================================================
// 1. INITIALIZATION & DATABASE
// ============================================================================
dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_123';

app.use(express.json({ limit: '50mb' }));
app.use(cors());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const __dirname_local = path.resolve();

// ============================================================================
// 2. UTILITIES & MIDDLEWARE
// ============================================================================
const generateToken = (id, role, isAdmin, adminRole) => {
    return jwt.sign({ id, role, isAdmin, adminRole }, JWT_SECRET, { expiresIn: '30d' });
};

const handleError = (res, error, message = 'Server Error') => {
    console.error(`[ERROR] ${message}:`, error);
    res.status(500).json({ message: error.message || message });
};

const protect = (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;
            next();
        } catch (error) {
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    } else {
        res.status(401).json({ message: 'Not authorized, no token' });
    }
};

const admin = (req, res, next) => {
    if (req.user && req.user.isAdmin) next();
    else res.status(403).json({ message: 'Admin access required' });
};

// ============================================================================
// 3. AUTHENTICATION (FULL ENDPOINTS)
// ============================================================================
app.post('/api/auth/register', async (req, res) => {
    const { 
        email, password, role, fullName, phoneNumber, state, city, otherCity, address,
        clientType, cleanerType, companyName, companyAddress, experience, services, bio,
        chargeHourly, chargeDaily, chargePerContract, chargePerContractNegotiable,
        bankName, accountNumber, profilePhoto, governmentId, businessRegDoc 
    } = req.body;

    try {
        const normalizedEmail = email.toLowerCase().trim();
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
        if (userExists.rows.length > 0) return res.status(400).json({ message: 'User already exists' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const servicesJson = services ? JSON.stringify(services) : '[]';

        const result = await pool.query(
            `INSERT INTO users (
                email, password_hash, role, full_name, phone_number, state, city, other_city, address,
                client_type, cleaner_type, company_name, company_address, experience, services, bio,
                charge_hourly, charge_daily, charge_per_contract, charge_per_contract_negotiable,
                bank_name, account_number, profile_photo, government_id, business_reg_doc, subscription_tier, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, 'Free', NOW()) RETURNING *`,
            [normalizedEmail, hashedPassword, role, fullName, phoneNumber, state, city, otherCity, address, clientType, cleanerType, companyName, companyAddress, experience, servicesJson, bio, chargeHourly, chargeDaily, chargePerContract, chargePerContractNegotiable, bankName, accountNumber, profilePhoto, governmentId, businessRegDoc]
        );

        res.status(201).json({ message: 'Registration successful!', success: true });
    } catch (error) { handleError(res, error, 'Registration failed'); }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const normalizedEmail = email.toLowerCase().trim();
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
        const user = result.rows[0];

        if (user && (await bcrypt.compare(password, user.password_hash))) {
            if (user.is_suspended) return res.status(403).json({ message: 'Account suspended.' });
            res.json({
                token: generateToken(user.id, user.role, user.is_admin, user.admin_role),
                user: { id: user.id, fullName: user.full_name, email: user.email, role: user.role, isAdmin: user.is_admin }
            });
        } else {
            res.status(401).json({ message: 'Invalid email or password' });
        }
    } catch (error) { handleError(res, error, 'Login failed'); }
});

// ============================================================================
// 4. CLEANER & USER PROFILE MANAGEMENT
// ============================================================================
app.get('/api/cleaners', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT u.*, COALESCE(AVG(r.rating), 5.0) as avg_rating, COUNT(r.id) as review_count
            FROM users u LEFT JOIN reviews r ON u.id = r.cleaner_id
            WHERE u.role = 'cleaner' AND u.is_suspended = false
            GROUP BY u.id
        `);
        res.json(result.rows);
    } catch (error) { handleError(res, error); }
});

app.get('/api/users/me', protect, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT u.*, 
            (SELECT json_agg(b.*) FROM bookings b WHERE b.client_id = u.id OR b.cleaner_id = u.id) as booking_history
            FROM users u WHERE u.id = $1`, [req.user.id]);
        if (!result.rows[0]) return res.status(404).json({ message: 'User not found' });
        res.json(result.rows[0]);
    } catch (error) { handleError(res, error); }
});

// ============================================================================
// 5. BOOKINGS, REVIEWS & CHAT
// ============================================================================
app.post('/api/bookings', protect, async (req, res) => {
    const { cleanerId, service, date, amount, totalAmount, paymentMethod } = req.body;
    try {
        const cleanerRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [cleanerId]);
        const result = await pool.query(
            `INSERT INTO bookings (client_id, cleaner_id, cleaner_name, service, date, amount, total_amount, payment_method, status, payment_status, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'Upcoming', 'Pending', NOW()) RETURNING *`,
            [req.user.id, cleanerId, cleanerRes.rows[0].full_name, service, date, amount, totalAmount, paymentMethod]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) { handleError(res, error); }
});

app.post('/api/reviews', protect, async (req, res) => {
    const { cleanerId, rating, comment, bookingId } = req.body;
    try {
        const result = await pool.query(
            `INSERT INTO reviews (cleaner_id, reviewer_id, rating, comment, booking_id, created_at)
             VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *`,
            [cleanerId, req.user.id, rating, comment, bookingId]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) { handleError(res, error); }
});

app.get('/api/chats', protect, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM chats WHERE client_id = $1 OR cleaner_id = $1', [req.user.id]);
        res.json(result.rows);
    } catch (error) { handleError(res, error); }
});

// ============================================================================
// 6. ADMIN MASTER CONTROL (COMPLETE)
// ============================================================================
app.get('/api/admin/dashboard', protect, admin, async (req, res) => {
    try {
        const clients = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'client'");
        const cleaners = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'cleaner'");
        const revenue = await pool.query("SELECT SUM(total_amount) FROM bookings WHERE payment_status = 'Confirmed'");
        res.json({
            totalClients: parseInt(clients.rows[0].count),
            totalCleaners: parseInt(cleaners.rows[0].count),
            totalRevenue: parseFloat(revenue.rows[0].sum || 0)
        });
    } catch (error) { handleError(res, error); }
});

app.get('/api/admin/users', protect, admin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) { handleError(res, error); }
});

app.patch('/api/admin/users/:id/status', protect, admin, async (req, res) => {
    try {
        await pool.query('UPDATE users SET is_suspended = $1 WHERE id = $2', [req.body.isSuspended, req.params.id]);
        res.json({ message: 'Status updated' });
    } catch (error) { handleError(res, error); }
});

// ============================================================================
// 7. PRODUCTION ASSETS & 404 HANDLING (STRICT ORDER)
// ============================================================================
if (process.env.NODE_ENV === 'production') {
    const distPath = path.join(__dirname_local, 'dist');
    app.use(express.static(distPath));

    app.get('*', (req, res) => {
        // Only serve index.html if the request isn't trying to reach an /api route
        if (!req.path.startsWith('/api/')) {
            res.sendFile(path.join(distPath, 'index.html'));
        } else {
            res.status(404).json({ message: 'API Endpoint not found' });
        }
    });
}

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));