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
// UTILITIES
// ============================================================================
const generateToken = (id, role, isAdmin, adminRole) => {
    return jwt.sign({ id, role, isAdmin, adminRole }, JWT_SECRET, { expiresIn: '30d' });
};

const sendEmail = async (to, subject, text) => {
    console.log(`\n--- [MOCK EMAIL] ---\nTo: ${to}\nSubject: ${subject}\nBody: ${text}\n--------------------\n`);
};

const handleError = (res, error, message = 'Server Error') => {
    console.error(message, error.stack || error);
    res.status(500).json({ message: error.message || message });
};

// ============================================================================
// MIDDLEWARE
// ============================================================================
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
// ROUTES: AUTH
// ============================================================================

app.post('/api/auth/register', async (req, res) => {
    const {
        email, password, role, fullName, phoneNumber, state, city, otherCity, address,
        clientType, cleanerType, companyName, companyAddress, experience, services, bio,
        chargeHourly, chargeDaily, chargePerContract, chargePerContractNegotiable,
        bankName, accountNumber, profilePhoto, governmentId, businessRegDoc
    } = req.body;

    try {
        const normalizedEmail = email.toLowerCase();
        
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
        const normalizedEmail = email.toLowerCase();
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
        const user = result.rows[0];

        if (user && (await bcrypt.compare(password, user.password_hash))) {
            if (user.is_suspended) return res.status(403).json({ message: 'Account is suspended.' });
            const userData = {
                id: user.id, fullName: user.full_name, email: user.email, role: user.role,
                isAdmin: user.is_admin, adminRole: user.admin_role, profilePhoto: user.profile_photo,
                subscriptionTier: user.subscription_tier
            };
            res.json({ token: generateToken(user.id, user.role, user.is_admin, user.admin_role), user: userData });
        } else {
            res.status(401).json({ message: 'Invalid email or password' });
        }
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
            FROM users u WHERE u.id = $1
        `, [req.user.id]);
        const user = result.rows[0];
        if (!user) return res.status(404).json({ message: 'User not found' });

        const formattedUser = {
            ...user,
            fullName: user.full_name,
            phoneNumber: user.phone_number,
            companyName: user.company_name,
            companyAddress: user.company_address,
            otherCity: user.other_city,
            profilePhoto: user.profile_photo,
            isAdmin: user.is_admin,
            adminRole: user.admin_role,
            subscriptionTier: user.subscription_tier,
            cleanerType: user.cleaner_type,
            clientType: user.client_type,
            chargeHourly: user.charge_hourly,
            chargeDaily: user.charge_daily,
            chargePerContract: user.charge_per_contract,
            chargePerContractNegotiable: user.charge_per_contract_negotiable,
            bankName: user.bank_name,
            accountNumber: user.account_number,
            pendingSubscription: user.pending_subscription,
            isSuspended: user.is_suspended,
            governmentId: user.government_id,
            businessRegDoc: user.business_reg_doc,
            services: typeof user.services === 'string' ? JSON.parse(user.services) : (user.services || []),
            bookingHistory: user.booking_history || [],
            reviewsData: user.reviews_data || [],
            subscriptionReceipt: user.subscription_receipt ? JSON.parse(user.subscription_receipt) : null
        };
        res.json(formattedUser);
    } catch (error) { handleError(res, error); }
});

app.put('/api/users/me', protect, async (req, res) => {
    const { fullName, phoneNumber, address, bio, services, experience, chargeHourly, chargeDaily, chargePerContract, chargePerContractNegotiable, profilePhoto, state, city, otherCity, companyName, companyAddress, bankName, accountNumber } = req.body;
    try {
        const result = await pool.query(
            `UPDATE users SET
            full_name = COALESCE($1, full_name), phone_number = COALESCE($2, phone_number), address = COALESCE($3, address),
            bio = COALESCE($4, bio), services = COALESCE($5, services), experience = COALESCE($6, experience),
            charge_hourly = COALESCE($7, charge_hourly), charge_daily = COALESCE($8, charge_daily),
            charge_per_contract = COALESCE($9, charge_per_contract), profile_photo = COALESCE($10, profile_photo),
            state = COALESCE($11, state), city = COALESCE($12, city), other_city = COALESCE($13, other_city),
            company_name = COALESCE($14, company_name), company_address = COALESCE($15, company_address),
            bank_name = COALESCE($16, bank_name), account_number = COALESCE($17, account_number),
            charge_per_contract_negotiable = COALESCE($18, charge_per_contract_negotiable)
            WHERE id = $19 RETURNING *`,
            [fullName, phoneNumber, address, bio, services ? JSON.stringify(services) : null, experience, chargeHourly, chargeDaily, chargePerContract, profilePhoto, state, city, otherCity, companyName, companyAddress, bankName, accountNumber, chargePerContractNegotiable, req.user.id]
        );
        res.json(result.rows[0]);
    } catch (error) { handleError(res, error, 'Update failed'); }
});

app.get('/api/cleaners', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT u.*, COALESCE(AVG(r.rating), 5.0) as avg_rating, COUNT(r.id) as review_count,
            (SELECT json_agg(revs) FROM (SELECT reviewer_name, rating, comment, created_at FROM reviews WHERE cleaner_id = u.id ORDER BY created_at DESC LIMIT 3) revs) as recent_reviews
            FROM users u LEFT JOIN reviews r ON u.id = r.cleaner_id
            WHERE u.role = 'cleaner' AND u.is_suspended = false
            GROUP BY u.id
        `);
        const cleaners = result.rows.map(c => ({
            id: c.id, name: c.full_name, photoUrl: c.profile_photo, rating: parseFloat(parseFloat(c.avg_rating).toFixed(1)),
            reviews: parseInt(c.review_count), serviceTypes: typeof c.services === 'string' ? JSON.parse(c.services) : (c.services || []),
            state: c.state, city: c.city, otherCity: c.other_city, experience: c.experience, bio: c.bio,
            isVerified: !!c.business_reg_doc, chargeHourly: c.charge_hourly, chargeDaily: c.charge_daily,
            chargePerContract: c.charge_per_contract, chargePerContractNegotiable: c.charge_per_contract_negotiable,
            subscriptionTier: c.subscription_tier, cleanerType: c.cleaner_type, reviewsData: c.recent_reviews || []
        }));
        res.json(cleaners);
    } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: BOOKINGS
// ============================================================================

app.post('/api/bookings', protect, async (req, res) => {
    const { cleanerId, service, date, amount, totalAmount, paymentMethod } = req.body;
    try {
        const cleanerRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [cleanerId]);
        const clientRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [req.user.id]);
        const cleanerName = cleanerRes.rows[0]?.full_name || 'Cleaner';
        const clientName = clientRes.rows[0]?.full_name || 'Client';

        const result = await pool.query(
            `INSERT INTO bookings (client_id, cleaner_id, client_name, cleaner_name, service, date, amount, total_amount, payment_method, status, payment_status, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'Upcoming', $10, NOW()) RETURNING *`,
            [req.user.id, cleanerId, clientName, cleanerName, service, date, amount, totalAmount, paymentMethod, paymentMethod === 'Direct' ? 'Not Applicable' : 'Pending Payment']
        );
        res.status(201).json(result.rows[0]);
    } catch (error) { handleError(res, error, 'Booking failed'); }
});

app.post('/api/bookings/:id/complete', protect, async (req, res) => {
    try {
        const bookingRes = await pool.query('SELECT * FROM bookings WHERE id = $1', [req.params.id]);
        const booking = bookingRes.rows[0];
        let newPaymentStatus = booking.payment_status;
        if (booking.payment_method === 'Escrow' && booking.payment_status === 'Confirmed') newPaymentStatus = 'Pending Payout';

        const result = await pool.query("UPDATE bookings SET status = 'Completed', job_approved_by_client = true, payment_status = $1 WHERE id = $2 RETURNING *", [newPaymentStatus, req.params.id]);
        res.json(result.rows[0]);
    } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: REVIEWS
// ============================================================================

app.post('/api/reviews', protect, async (req, res) => {
    const { cleanerId, rating, comment, bookingId } = req.body;
    try {
        const cleanerRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [cleanerId]);
        const clientRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [req.user.id]);
        const result = await pool.query(
            `INSERT INTO reviews (cleaner_id, cleaner_name, reviewer_id, reviewer_name, rating, comment, booking_id, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING *`,
            [cleanerId, cleanerRes.rows[0].full_name, req.user.id, clientRes.rows[0].full_name, rating, comment, bookingId]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) { handleError(res, error, 'Review submission failed'); }
});

// ============================================================================
// ROUTES: CHAT & MESSAGES (FIXED)
// ============================================================================



app.get('/api/chats', protect, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM chats WHERE client_id = $1 OR cleaner_id = $1 ORDER BY updated_at DESC', [req.user.id]);
        res.json(result.rows);
    } catch (error) { handleError(res, error, 'Fetching chats failed'); }
});

app.post('/api/chats', protect, async (req, res) => {
    const { recipientId } = req.body;
    try {
        const existing = await pool.query('SELECT * FROM chats WHERE (client_id = $1 AND cleaner_id = $2) OR (client_id = $2 AND cleaner_id = $1)', [req.user.id, recipientId]);
        if (existing.rows.length > 0) return res.json(existing.rows[0]);
        const result = await pool.query('INSERT INTO chats (client_id, cleaner_id, created_at, updated_at) VALUES ($1, $2, NOW(), NOW()) RETURNING *', [req.user.id, recipientId]);
        res.status(201).json(result.rows[0]);
    } catch (error) { handleError(res, error, 'Create chat failed'); }
});

app.get('/api/chats/:chatId/messages', protect, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM messages WHERE chat_id = $1 ORDER BY created_at ASC', [req.params.chatId]);
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
// ROUTES: SUPPORT (NEWLY ADDED TO FIX 404)
// ============================================================================

app.get('/api/support/my', protect, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM support_tickets WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
        res.json(result.rows);
    } catch (error) { res.json([]); }
});

app.post('/api/support/tickets', protect, async (req, res) => {
    const { subject, description, priority } = req.body;
    try {
        const userRes = await pool.query('SELECT full_name, email FROM users WHERE id = $1', [req.user.id]);
        const result = await pool.query(
            `INSERT INTO support_tickets (user_id, user_name, user_email, subject, description, priority, status, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, 'Open', NOW()) RETURNING *`,
            [req.user.id, userRes.rows[0].full_name, userRes.rows[0].email, subject, description, priority]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) { handleError(res, error, 'Ticket failed'); }
});

// ============================================================================
// ROUTES: ADMIN & SUBSCRIPTIONS
// ============================================================================

app.get('/api/admin/dashboard', protect, admin, async (req, res) => {
    try {
        const clientCount = (await pool.query("SELECT COUNT(*) FROM users WHERE role = 'client'")).rows[0].count;
        const cleanerCount = (await pool.query("SELECT COUNT(*) FROM users WHERE role = 'cleaner'")).rows[0].count;
        const pendingBookings = (await pool.query("SELECT COUNT(*) FROM bookings WHERE status = 'Upcoming'")).rows[0].count;
        const totalRevenue = (await pool.query("SELECT SUM(total_amount) FROM bookings WHERE payment_status = 'Confirmed'")).rows[0].sum || 0;
        res.json({ clientCount, cleanerCount, pendingBookings, totalRevenue });
    } catch (error) { handleError(res, error); }
});

app.post('/api/subscriptions/proof', protect, async (req, res) => {
    const { pendingSubscription, subscriptionReceipt } = req.body;
    try {
        const result = await pool.query("UPDATE users SET pending_subscription = $1, subscription_receipt = $2 WHERE id = $3 RETURNING *", [pendingSubscription, JSON.stringify(subscriptionReceipt), req.user.id]);
        res.json(result.rows[0]);
    } catch (error) { handleError(res, error); }
});

// Final 404 and Listen
app.use('/api/*', (req, res) => res.status(404).json({ message: `API Not Found - ${req.originalUrl}` }));

if (process.env.NODE_ENV === 'production') {
    const distPath = path.join(__dirname_local, 'dist');
    if (fs.existsSync(distPath)) {
        app.use(express.static(distPath));
        app.get('*', (req, res) => res.sendFile(path.join(distPath, 'index.html')));
    }
}
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));