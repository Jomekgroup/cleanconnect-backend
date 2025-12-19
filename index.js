const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

// ============================================================================
// CONFIGURATION
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
// UTILITIES & MIDDLEWARE
// ============================================================================
const generateToken = (id, role, isAdmin, adminRole) => {
    return jwt.sign({ id, role, isAdmin, adminRole }, JWT_SECRET, { expiresIn: '30d' });
};

const handleError = (res, error, message = 'Server Error') => {
    console.error(message, error.stack || error);
    res.status(500).json({ message: error.message || message });
};

const protect = (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            token = req.headers.authorization.split(' ')[1];
            req.user = jwt.verify(token, JWT_SECRET);
            next();
        } catch (error) { res.status(401).json({ message: 'Not authorized' }); }
    } else { res.status(401).json({ message: 'No token' }); }
};

const admin = (req, res, next) => {
    if (req.user && req.user.isAdmin) next();
    else res.status(403).json({ message: 'Admin access required' });
};

// ============================================================================
// ROUTES: AUTH (FIXED FOR 401 ERRORS)
// ============================================================================
app.post('/api/auth/register', async (req, res) => {
    const { email, password, role, fullName, ...rest } = req.body;
    try {
        const normalizedEmail = email.toLowerCase().trim();
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
        if (userExists.rows.length > 0) return res.status(400).json({ message: 'User already exists' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const servicesJson = rest.services ? JSON.stringify(rest.services) : '[]';

        const result = await pool.query(
            `INSERT INTO users (
                email, password_hash, role, full_name, phone_number, state, city, other_city, address,
                client_type, cleaner_type, company_name, company_address, experience, services, bio,
                charge_hourly, charge_daily, charge_per_contract, charge_per_contract_negotiable,
                bank_name, account_number, profile_photo, government_id, business_reg_doc, subscription_tier, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, 'Free', NOW()) RETURNING *`,
            [normalizedEmail, hashedPassword, role, fullName, rest.phoneNumber, rest.state, rest.city, rest.otherCity, rest.address, rest.clientType, rest.cleanerType, rest.companyName, rest.companyAddress, rest.experience, servicesJson, rest.bio, rest.chargeHourly, rest.chargeDaily, rest.chargePerContract, rest.chargePerContractNegotiable, rest.bankName, rest.accountNumber, rest.profilePhoto, rest.governmentId, rest.businessRegDoc]
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
            if (user.is_suspended) return res.status(403).json({ message: 'Account is suspended.' });
            res.json({ token: generateToken(user.id, user.role, user.is_admin, user.admin_role), user: { id: user.id, fullName: user.full_name, email: user.email, role: user.role, isAdmin: user.is_admin } });
        } else { res.status(401).json({ message: 'Invalid email or password' }); }
    } catch (error) { handleError(res, error, 'Login failed'); }
});

// ============================================================================
// ROUTES: USERS & CLEANERS
// ============================================================================
app.get('/api/users/me', protect, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT u.*, 
            (SELECT json_agg(b.*) FROM bookings b WHERE b.client_id = u.id OR b.cleaner_id = u.id) as booking_history,
            (SELECT json_agg(r.*) FROM reviews r WHERE r.cleaner_id = u.id) as reviews_data
            FROM users u WHERE u.id = $1`, [req.user.id]);
        const user = result.rows[0];
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json({ ...user, services: typeof user.services === 'string' ? JSON.parse(user.services) : (user.services || []) });
    } catch (error) { handleError(res, error); }
});

app.get('/api/cleaners', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT u.*, COALESCE(AVG(r.rating), 5.0) as avg_rating, COUNT(r.id) as review_count
            FROM users u LEFT JOIN reviews r ON u.id = r.cleaner_id
            WHERE u.role = 'cleaner' AND u.is_suspended = false GROUP BY u.id`);
        res.json(result.rows);
    } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: BOOKINGS, REVIEWS, & CHAT
// ============================================================================
app.post('/api/bookings', protect, async (req, res) => {
    const { cleanerId, service, date, amount, totalAmount, paymentMethod } = req.body;
    try {
        const cleanerRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [cleanerId]);
        const clientRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [req.user.id]);
        const result = await pool.query(
            `INSERT INTO bookings (client_id, cleaner_id, client_name, cleaner_name, service, date, amount, total_amount, payment_method, status, payment_status, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'Upcoming', 'Pending', NOW()) RETURNING *`,
            [req.user.id, cleanerId, clientRes.rows[0].full_name, cleanerRes.rows[0].full_name, service, date, amount, totalAmount, paymentMethod]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) { handleError(res, error); }
});

app.get('/api/chats', protect, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM chats WHERE client_id = $1 OR cleaner_id = $1 ORDER BY updated_at DESC', [req.user.id]);
        res.json(result.rows);
    } catch (error) { handleError(res, error); }
});

app.post('/api/chats/:chatId/messages', protect, async (req, res) => {
    const { content } = req.body;
    try {
        const messageRes = await pool.query('INSERT INTO messages (chat_id, sender_id, content, created_at) VALUES ($1, $2, $3, NOW()) RETURNING *', [req.params.chatId, req.user.id, content]);
        await pool.query('UPDATE chats SET updated_at = NOW(), last_message_content = $1 WHERE id = $2', [content, req.params.chatId]);
        res.status(201).json(messageRes.rows[0]);
    } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: ADMIN DASHBOARD (MISSING IN SMALL CODE)
// ============================================================================
app.get('/api/admin/users', protect, admin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) { handleError(res, error); }
});

app.patch('/api/admin/users/:id/status', protect, admin, async (req, res) => {
    try {
        await pool.query('UPDATE users SET is_suspended = $1 WHERE id = $2', [req.body.isSuspended, req.params.id]);
        res.json({ message: 'User status updated' });
    } catch (error) { handleError(res, error); }
});

app.post('/api/admin/bookings/:id/confirm-payment', protect, admin, async (req, res) => {
    try {
        await pool.query("UPDATE bookings SET payment_status = 'Confirmed' WHERE id = $1", [req.params.id]);
        res.json({ message: 'Payment confirmed' });
    } catch (error) { handleError(res, error); }
});

// ============================================================================
// PRODUCTION & 404 (FIXED ORDER)
// ============================================================================
app.use('/api/*', (req, res) => res.status(404).json({ message: `API Not Found - ${req.originalUrl}` }));

if (process.env.NODE_ENV === 'production') {
    const distPath = path.join(__dirname_local, 'dist');
    if (fs.existsSync(distPath)) {
        app.use(express.static(distPath));
        app.get('*', (req, res) => res.sendFile(path.join(distPath, 'index.html')));
    }
}

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));