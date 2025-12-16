const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { GoogleGenAI } = require('@google/genai');
const serverless = require('serverless-http'); // <-- CRITICAL SERVERLESS IMPORT

// ============================================================================
// CONFIGURATION
// ============================================================================
dotenv.config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_123';

// Increase payload limit for Base64 image uploads
app.use(express.json({ limit: '50mb' }));

// ... in index.js around line 18
const allowedOrigins = [
  'http://localhost:5173',  
  'http://localhost:3000',
  'https://cleanconnect.vercel.app',
  'https://cleanconnect-frontend.vercel.app',
  // ADD THIS LINE:
  'https://cleanconnectapp-v2.vercel.app' 
];
// ... rest of the CORS middleware ...
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`CORS blocked origin: ${origin}`);
      callback(null, false); 
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Gemini AI Client
let ai;
try {
    if (process.env.API_KEY) {
        ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
    }
} catch (e) {
    console.warn("Google AI init failed. Ensure @google/genai is installed and API_KEY is set.");
}


// ============================================================================
// UTILITIES
// ============================================================================
const generateToken = (id, role, isAdmin, adminRole) => {
  return jwt.sign({ id, role, isAdmin, adminRole }, JWT_SECRET, { expiresIn: '30d' });
};

const sendEmail = async (to, subject, text) => {
  if (process.env.NODE_ENV !== 'test') {
    console.log(`\n--- [MOCK EMAIL] ---\nTo: ${to}\nSubject: ${subject}\nBody: ${text}\n--------------------\n`);
  }
};

const handleError = (res, error, message = 'Server Error') => {
  console.error(message, error);
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
// ROUTES: HEALTH CHECK & ROOT
// ============================================================================
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'CleanConnect Backend API',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

app.get('/', (req, res) => {
  res.json({ 
    message: 'CleanConnect Backend API',
    version: '1.0.0',
  });
});

// ============================================================================
// ROUTES: AUTH
// ============================================================================
app.post('/api/auth/register', async (req, res) => {
  const { email, password, role, fullName, phoneNumber, state, city, otherCity, address, clientType, cleanerType, companyName, companyAddress, experience, services, bio, chargeHourly, chargeDaily, chargePerContract, chargePerContractNegotiable, bankName, accountNumber, profilePhoto, governmentId, businessRegDoc } = req.body;

  try {
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) return res.status(400).json({ message: 'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const servicesJson = services ? JSON.stringify(services) : null; 

    const result = await pool.query(
      `INSERT INTO users (
        email, password_hash, role, full_name, phone_number, state, city, other_city, address, 
        client_type, cleaner_type, company_name, company_address, experience, services, bio, 
        charge_hourly, charge_daily, charge_per_contract, charge_per_contract_negotiable,
        bank_name, account_number, profile_photo, government_id, business_reg_doc, subscription_tier, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, 'Free', NOW()) RETURNING id, full_name, email, role, is_admin, admin_role, subscription_tier, profile_photo`,
      [email, hashedPassword, role, fullName, phoneNumber, state, city, otherCity, address, clientType, cleanerType, companyName, companyAddress, experience, servicesJson, bio, chargeHourly, chargeDaily, chargePerContract, chargePerContractNegotiable, bankName, accountNumber, profilePhoto, governmentId, businessRegDoc]
    );

    const user = result.rows[0];
    res.status(201).json({
      id: user.id,
      fullName: user.full_name,
      email: user.email,
      role: user.role,
      isAdmin: user.is_admin,
      adminRole: user.admin_role,
      profilePhoto: user.profile_photo,
      subscriptionTier: user.subscription_tier,
      token: generateToken(user.id, user.role, user.is_admin, user.admin_role)
    });
  } catch (error) { handleError(res, error, 'Registration failed'); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT id, full_name, email, role, is_admin, admin_role, profile_photo, subscription_tier, password_hash, is_suspended FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (user && (await bcrypt.compare(password, user.password_hash))) {
      if (user.is_suspended) return res.status(403).json({ message: 'Account is suspended.' });
      
      const userData = {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        role: user.role,
        isAdmin: user.is_admin,
        adminRole: user.admin_role,
        profilePhoto: user.profile_photo,
        subscriptionTier: user.subscription_tier,
      };
      
      res.json({ token: generateToken(user.id, user.role, user.is_admin, user.admin_role), user: userData });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) { handleError(res, error, 'Login failed'); }
});

// ============================================================================
// ROUTES: ADMIN SEEDING
// ============================================================================
app.get('/api/seed-admins', async (req, res) => {
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash('password', salt);
    
    const admins = [
      { email: 'super@cleanconnect.ng', name: 'Super Admin', role: 'Super' },
      { email: 'payment@cleanconnect.ng', name: 'Payment Admin', role: 'Payment' },
      { email: 'verification@cleanconnect.ng', name: 'Verification Admin', role: 'Verification' },
      { email: 'support@cleanconnect.ng', name: 'Support Admin', role: 'Support' }
    ];

    const results = [];
    for (const admin of admins) {
       const exists = await pool.query('SELECT id FROM users WHERE email = $1', [admin.email]);
       if (exists.rows.length === 0) {
         const result = await pool.query(
           `INSERT INTO users (full_name, email, password_hash, role, is_admin, admin_role, phone_number, created_at)
            VALUES ($1, $2, $3, 'admin', true, $4, '0000000000', NOW()) RETURNING id, email, admin_role`,
           [admin.name, admin.email, hashedPassword, admin.role]
         );
         results.push(result.rows[0]);
       }
    }
    
    res.json({ 
        message: 'Admin seeding complete', 
        created: results,
        info: 'Default password is "password"' 
    });
  } catch (error) {
    handleError(res, error, 'Seeding failed'); 
  }
});

// ============================================================================
// ROUTES: USERS & CLEANERS
// ============================================================================
app.get('/api/users/me', protect, async (req, res) => {
  try {
    // 1. Fetch User Data (Explicitly select non-sensitive columns)
    const userResult = await pool.query(`
      SELECT 
        id, full_name, email, role, phone_number, address, state, city, other_city, 
        profile_photo, is_admin, admin_role, subscription_tier, cleaner_type, client_type, 
        company_name, company_address, experience, services, bio, charge_hourly, 
        charge_daily, charge_per_contract, charge_per_contract_negotiable, bank_name, 
        account_number, pending_subscription, subscription_receipt, is_suspended, 
        government_id, business_reg_doc
      FROM users WHERE id = $1
    `, [req.user.id]);
    
    const user = userResult.rows[0];
    if (!user) return res.status(404).json({ message: 'User not found' });

    // 2. Fetch Bookings Separately (More efficient than json_agg subquery)
    const bookingsResult = await pool.query(
      'SELECT * FROM bookings WHERE client_id = $1 OR cleaner_id = $1 ORDER BY created_at DESC', 
      [req.user.id]
    );

    // 3. Fetch Reviews Separately (More efficient than json_agg subquery)
    const reviewsResult = await pool.query(
      'SELECT * FROM reviews WHERE cleaner_id = $1 ORDER BY created_at DESC', 
      [req.user.id]
    );

    // 4. Combine and Format
    const formattedUser = {
      id: user.id,
      fullName: user.full_name,
      email: user.email,
      role: user.role,
      phoneNumber: user.phone_number,
      address: user.address,
      state: user.state,
      city: user.city,
      otherCity: user.other_city,
      profilePhoto: user.profile_photo,
      isAdmin: user.is_admin,
      adminRole: user.admin_role,
      subscriptionTier: user.subscription_tier,
      cleanerType: user.cleaner_type,
      clientType: user.client_type,
      companyName: user.company_name,
      companyAddress: user.company_address,
      experience: user.experience,
      bio: user.bio,
      services: typeof user.services === 'string' ? JSON.parse(user.services) : user.services,
      chargeHourly: user.charge_hourly,
      chargeDaily: user.charge_daily,
      chargePerContract: user.charge_per_contract,
      chargePerContractNegotiable: user.charge_per_contract_negotiable,
      bankName: user.bank_name,
      accountNumber: user.account_number,
      bookingHistory: bookingsResult.rows || [], 
      reviewsData: reviewsResult.rows || [],    
      pendingSubscription: user.pending_subscription,
      subscriptionReceipt: user.subscription_receipt ? JSON.parse(user.subscription_receipt) : null,
      isSuspended: user.is_suspended,
      governmentId: user.government_id,
      businessRegDoc: user.business_reg_doc
    };

    res.json(formattedUser);
  } catch (error) { handleError(res, error); }
});

app.put('/api/users/me', protect, async (req, res) => {
  const { fullName, phoneNumber, address, bio, services, experience, chargeHourly, chargeDaily, chargePerContract, chargePerContractNegotiable, profilePhoto, state, city, otherCity, companyName, companyAddress, bankName, accountNumber } = req.body;
  try {
    const result = await pool.query(
      `UPDATE users SET 
        full_name = COALESCE($1, full_name),
        phone_number = COALESCE($2, phone_number),
        address = COALESCE($3, address),
        bio = COALESCE($4, bio),
        services = COALESCE($5, services),
        experience = COALESCE($6, experience),
        charge_hourly = COALESCE($7, charge_hourly),
        charge_daily = COALESCE($8, charge_daily),
        charge_per_contract = COALESCE($9, charge_per_contract),
        profile_photo = COALESCE($10, profile_photo),
        state = COALESCE($11, state),
        city = COALESCE($12, city),
        other_city = COALESCE($13, other_city),
        company_name = COALESCE($14, company_name),
        company_address = COALESCE($15, company_address),
        bank_name = COALESCE($16, bank_name),
        account_number = COALESCE($17, account_number),
        charge_per_contract_negotiable = COALESCE($18, charge_per_contract_negotiable)
       WHERE id = $19 RETURNING id, full_name, email, role, is_admin, admin_role, subscription_tier, profile_photo`,
      [fullName, phoneNumber, address, bio, services ? JSON.stringify(services) : null, experience, chargeHourly, chargeDaily, chargePerContract, profilePhoto, state, city, otherCity, companyName, companyAddress, bankName, accountNumber, chargePerContractNegotiable, req.user.id]
    );
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error, 'Update failed'); }
});

app.get('/api/cleaners', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.id, u.full_name, u.profile_photo, u.services, u.state, u.city, u.other_city, 
        u.experience, u.bio, u.business_reg_doc, u.charge_hourly, u.charge_daily, 
        u.charge_per_contract, u.charge_per_contract_negotiable, u.subscription_tier, 
        u.cleaner_type,
        COALESCE(AVG(r.rating), 5.0) as avg_rating,
        COUNT(r.id) as review_count,
        (
          SELECT json_agg(revs) 
          FROM (
            SELECT reviewer_name, rating, comment, created_at 
            FROM reviews 
            WHERE cleaner_id = u.id 
            ORDER BY created_at DESC 
            LIMIT 3
          ) revs
        ) as recent_reviews
      FROM users u
      LEFT JOIN reviews r ON u.id = r.cleaner_id
      WHERE u.role = 'cleaner' AND u.is_suspended = false
      GROUP BY u.id
    `);

    const cleaners = result.rows.map(c => ({
      id: c.id,
      name: c.full_name,
      photoUrl: c.profile_photo,
      rating: parseFloat(parseFloat(c.avg_rating).toFixed(1)),
      reviews: parseInt(c.review_count),
      serviceTypes: typeof c.services === 'string' ? JSON.parse(c.services) : (c.services || []),
      state: c.state,
      city: c.city,
      otherCity: c.other_city,
      experience: c.experience,
      bio: c.bio,
      isVerified: !!c.business_reg_doc,
      chargeHourly: c.charge_hourly,
      chargeDaily: c.charge_daily,
      chargePerContract: c.charge_per_contract,
      chargePerContractNegotiable: c.charge_per_contract_negotiable,
      subscriptionTier: c.subscription_tier,
      cleanerType: c.cleaner_type,
      reviewsData: c.recent_reviews || []
    }));
    res.json(cleaners);
  } catch (error) { handleError(res, error); }
});

app.get('/api/cleaners/:id', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                u.id, u.full_name, u.profile_photo, u.services, u.state, u.city, u.other_city, 
                u.experience, u.bio, u.business_reg_doc, u.charge_hourly, u.charge_daily, 
                u.charge_per_contract, u.charge_per_contract_negotiable, u.subscription_tier, 
                u.cleaner_type,
                COALESCE(AVG(r.rating), 5.0) as avg_rating,
                COUNT(r.id) as review_count,
                (SELECT json_agg(r.*) FROM reviews r WHERE r.cleaner_id = u.id) as reviews_data
            FROM users u
            LEFT JOIN reviews r ON u.id = r.cleaner_id
            WHERE u.id = $1 AND u.role = 'cleaner'
            GROUP BY u.id
        `, [req.params.id]);

        const c = result.rows[0];
        if (!c) return res.status(404).json({ message: 'Cleaner not found' });

        const cleaner = {
            id: c.id,
            name: c.full_name,
            photoUrl: c.profile_photo,
            rating: parseFloat(parseFloat(c.avg_rating).toFixed(1)),
            reviews: parseInt(c.review_count),
            serviceTypes: typeof c.services === 'string' ? JSON.parse(c.services) : (c.services || []),
            state: c.state,
            city: c.city,
            otherCity: c.other_city,
            experience: c.experience,
            bio: c.bio,
            isVerified: !!c.business_reg_doc,
            chargeHourly: c.charge_hourly,
            chargeDaily: c.charge_daily,
            chargePerContract: c.charge_per_contract,
            chargePerContractNegotiable: c.charge_per_contract_negotiable,
            subscriptionTier: c.subscription_tier,
            cleanerType: c.cleaner_type,
            reviewsData: c.reviews_data || []
        };
        res.json(cleaner);
    } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: BOOKINGS
// ============================================================================
app.post('/api/bookings', protect, async (req, res) => {
  const { cleanerId, service, date, amount, totalAmount, paymentMethod } = req.body;
  try {
    const cleanerRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [cleanerId]);
    const cleanerName = cleanerRes.rows[0]?.full_name || 'Cleaner';
    
    const clientRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [req.user.id]);
    const clientName = clientRes.rows[0]?.full_name || 'Client';

    const result = await pool.query(
      `INSERT INTO bookings (
        client_id, cleaner_id, client_name, cleaner_name, service, date, amount, total_amount, payment_method, status, payment_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'Upcoming', $10, NOW()) RETURNING *`,
      [req.user.id, cleanerId, clientName, cleanerName, service, date, amount, totalAmount, paymentMethod, paymentMethod === 'Direct' ? 'Not Applicable' : 'Pending Payment']
    );

    const b = result.rows[0];
    const booking = {
        id: b.id,
        clientId: b.client_id,
        cleanerId: b.cleaner_id,
        clientName: b.client_name,
        cleanerName: b.cleaner_name,
        service: b.service,
        date: b.date,
        amount: b.amount,
        totalAmount: b.total_amount,
        paymentMethod: b.payment_method,
        status: b.status,
        paymentStatus: b.payment_status,
        jobApprovedByClient: b.job_approved_by_client,
        reviewSubmitted: b.review_submitted
    };

    await sendEmail(req.user.id, 'Booking Confirmation', `You booked ${cleanerName} for ${service}.`);
    res.status(201).json(booking);
  } catch (error) { handleError(res, error, 'Booking failed'); }
});

app.post('/api/bookings/:id/cancel', protect, async (req, res) => {
  try {
    const result = await pool.query("UPDATE bookings SET status = 'Cancelled' WHERE id = $1 RETURNING *", [req.params.id]);
    const b = result.rows[0];
    res.json({ ...b, paymentStatus: b.payment_status, cleanerName: b.cleaner_name, clientName: b.client_name, totalAmount: b.total_amount, cleanerId: b.cleaner_id, clientId: b.client_id });
  } catch (error) { handleError(res, error); }
});

app.post('/api/bookings/:id/complete', protect, async (req, res) => {
  try {
    const bookingRes = await pool.query('SELECT * FROM bookings WHERE id = $1', [req.params.id]);
    const booking = bookingRes.rows[0];
    
    let newPaymentStatus = booking.payment_status;
    if (booking.payment_method === 'Escrow' && booking.payment_status === 'Confirmed') {
      newPaymentStatus = 'Pending Payout';
    }

    const result = await pool.query(
      "UPDATE bookings SET status = 'Completed', job_approved_by_client = true, payment_status = $1 WHERE id = $2 RETURNING *", 
      [newPaymentStatus, req.params.id]
    );
    const b = result.rows[0];
    res.json({ ...b, paymentStatus: b.payment_status, cleanerName: b.cleaner_name, clientName: b.client_name, totalAmount: b.total_amount, cleanerId: b.cleaner_id, clientId: b.client_id, jobApprovedByClient: b.job_approved_by_client });
  } catch (error) { handleError(res, error); }
});

app.post('/api/bookings/:id/review', protect, async (req, res) => {
  const { rating, timeliness, thoroughness, conduct, comment, cleanerId } = req.body;
  try {
    const clientRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [req.user.id]);
    const reviewerName = clientRes.rows[0]?.full_name || 'Anonymous';

    await pool.query(
      `INSERT INTO reviews (booking_id, cleaner_id, reviewer_name, rating, timeliness, thoroughness, conduct, comment, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
      [req.params.id, cleanerId, reviewerName, rating, timeliness, thoroughness, conduct, comment]
    );
    
    await pool.query("UPDATE bookings SET review_submitted = true WHERE id = $1", [req.params.id]);
    res.json({ message: 'Review submitted' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/bookings/:id/receipt', protect, async (req, res) => {
  const { name, dataUrl } = req.body;
  try {
    const receiptJson = JSON.stringify({ name, dataUrl });
    const result = await pool.query(
      "UPDATE bookings SET payment_receipt = $1, payment_status = 'Pending Admin Confirmation' WHERE id = $2 RETURNING *",
      [receiptJson, req.params.id]
    );
    res.json(result.rows[0]); 
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: SUBSCRIPTION
// ============================================================================
app.post('/api/users/subscription/upgrade', protect, async (req, res) => {
  const { plan } = req.body;
  try {
    const result = await pool.query(
      "UPDATE users SET pending_subscription = $1 WHERE id = $2 RETURNING *",
      [plan, req.user.id]
    );
    const u = result.rows[0];
    res.json({ id: u.id, fullName: u.full_name, subscriptionTier: u.subscription_tier, pendingSubscription: u.pending_subscription });
  } catch (error) { handleError(res, error); }
});

app.post('/api/users/subscription/receipt', protect, async (req, res) => {
  const { name, dataUrl } = req.body;
  try {
    const receiptJson = JSON.stringify({ name, dataUrl });
    const result = await pool.query(
      "UPDATE users SET subscription_receipt = $1 WHERE id = $2 RETURNING *",
      [receiptJson, req.user.id]
    );
    const u = result.rows[0];
    res.json({ id: u.id, fullName: u.full_name, subscriptionReceipt: JSON.parse(u.subscription_receipt) });
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: ADMIN
// ============================================================================
app.get('/api/admin/users', protect, admin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id, full_name, email, role, is_admin, admin_role, is_suspended, 
        subscription_tier, pending_subscription, subscription_receipt, 
        client_type, cleaner_type, company_name, created_at
      FROM users ORDER BY created_at DESC
    `);
    res.json(result.rows.map(u => ({
        id: u.id,
        fullName: u.full_name,
        email: u.email,
        role: u.role,
        isAdmin: u.is_admin,
        adminRole: u.admin_role,
        isSuspended: u.is_suspended,
        subscriptionTier: u.subscription_tier,
        pendingSubscription: u.pending_subscription,
        subscriptionReceipt: u.subscription_receipt ? JSON.parse(u.subscription_receipt) : null,
        clientType: u.client_type,
        cleanerType: u.cleaner_type,
        companyName: u.company_name,
        bookingHistory: [] 
    })));
  } catch (error) { handleError(res, error); }
});

app.patch('/api/admin/users/:id/status', protect, admin, async (req, res) => {
  const { isSuspended } = req.body;
  try {
    await pool.query('UPDATE users SET is_suspended = $1 WHERE id = $2', [isSuspended, req.params.id]);
    res.json({ message: 'User status updated' });
  } catch (error) { handleError(res, error); }
});

app.delete('/api/admin/users/:id', protect, admin, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ message: 'User deleted' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/bookings/:id/confirm-payment', protect, admin, async (req, res) => {
  try {
    await pool.query("UPDATE bookings SET payment_status = 'Confirmed' WHERE id = $1", [req.params.id]);
    res.json({ message: 'Payment confirmed' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/bookings/:id/mark-paid', protect, admin, async (req, res) => {
  try {
    await pool.query("UPDATE bookings SET payment_status = 'Paid' WHERE id = $1", [req.params.id]);
    res.json({ message: 'Marked as paid' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/users/:id/approve-subscription', protect, admin, async (req, res) => {
  try {
    const userRes = await pool.query('SELECT pending_subscription FROM users WHERE id = $1', [req.params.id]);
    const plan = userRes.rows[0]?.pending_subscription;
    if (!plan) return res.status(400).json({ message: 'No pending subscription' });

    await pool.query(
      "UPDATE users SET subscription_tier = $1, pending_subscription = NULL, subscription_receipt = NULL WHERE id = $2",
      [plan, req.params.id]
    );
    res.json({ message: 'Subscription approved' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/create-admin', protect, admin, async (req, res) => {
  const { fullName, email, password, role } = req.body;
  try {
     const salt = await bcrypt.genSalt(10);
     const hashedPassword = await bcrypt.hash(password, salt);
     const result = await pool.query(
         `INSERT INTO users (full_name, email, password_hash, role, is_admin, admin_role, created_at)
          VALUES ($1, $2, $3, 'admin', true, $4, NOW()) RETURNING *`,
         [fullName, email, hashedPassword, role]
     );
     const u = result.rows[0];
     res.status(201).json({ id: u.id, fullName: u.full_name, isAdmin: u.is_admin, adminRole: u.admin_role });
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: SUPPORT TICKETS
// ============================================================================
app.post('/api/support', protect, async (req, res) => {
    const { category, subject, message } = req.body;
    try {
        const result = await pool.query(
            "INSERT INTO support_tickets (user_id, category, subject, message, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING *",
            [req.user.id, category, subject, message]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) { 
        handleError(res, error);
    }
});

app.get('/api/support/my', protect, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM support_tickets WHERE user_id = $1 ORDER BY created_at DESC", [req.user.id]);
        res.json(result.rows.map(r => ({
            id: r.id,
            userId: r.user_id,
            category: r.category,
            subject: r.subject,
            message: r.message,
            status: r.status || 'Open',
            adminResponse: r.admin_response,
            createdAt: r.created_at,
            updatedAt: r.updated_at
        })));
    } catch (error) { 
        handleError(res, error);
    }
});

app.get('/api/admin/support', protect, admin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT st.*, u.full_name, u.role 
            FROM support_tickets st 
            JOIN users u ON st.user_id = u.id 
            ORDER BY st.status ASC, st.created_at DESC
        `);
        
        res.json(result.rows.map(r => ({
            id: r.id,
            userId: r.user_id,
            userName: r.full_name || 'Unknown',
            userRole: r.role || 'User',
            category: r.category,
            subject: r.subject,
            message: r.message,
            status: r.status || 'Open',
            adminResponse: r.admin_response,
            createdAt: r.created_at,
            updatedAt: r.updated_at
        })));
    } catch (error) { 
        handleError(res, error);
    }
});

app.post('/api/admin/support/:id/resolve', protect, admin, async (req, res) => {
    const { adminResponse } = req.body;
    try {
        const result = await pool.query(
            "UPDATE support_tickets SET admin_response = $1, status = 'Resolved', updated_at = NOW() WHERE id = $2 RETURNING *",
            [adminResponse, req.params.id]
        );
        res.json(result.rows[0]);
    } catch (error) { 
        handleError(res, error);
    }
});

// ============================================================================
// ROUTES: CHAT
// ============================================================================
app.post('/api/chats', protect, async (req, res) => {
    const { participantId } = req.body;
    const userId = req.user.id;

    try {
        // Check if chat already exists
        const existingChat = await pool.query(
            `SELECT * FROM chats WHERE (participant_one = $1 AND participant_two = $2) OR (participant_one = $2 AND participant_two = $1)`,
            [userId, participantId]
        );

        if (existingChat.rows.length > 0) {
            return res.json({ id: existingChat.rows[0].id, participants: [existingChat.rows[0].participant_one, existingChat.rows[0].participant_two], participantNames: {} }); 
        }

        const result = await pool.query(
            'INSERT INTO chats (participant_one, participant_two) VALUES ($1, $2) RETURNING *',
            [userId, participantId]
        );
        res.status(201).json({ id: result.rows[0].id, participants: [userId, participantId], participantNames: {} });
    } catch (error) { 
        handleError(res, error, 'Failed to create chat'); 
    }
});

app.get('/api/chats', protect, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT c.*, 
                    m.text as last_message_text, 
                    m.sender_id as last_message_sender, 
                    m.created_at as last_message_time,
                    u1.full_name as name1, u2.full_name as name2
             FROM chats c
             LEFT JOIN messages m ON c.last_message_id = m.id
             JOIN users u1 ON c.participant_one = u1.id
             JOIN users u2 ON c.participant_two = u2.id
             WHERE c.participant_one = $1 OR c.participant_two = $1
             ORDER BY m.created_at DESC NULLS LAST`,
            [req.user.id]
        );

        const chats = result.rows.map(row => ({
            id: row.id,
            participants: [row.participant_one, row.participant_two],
            participantNames: {
                [row.participant_one]: row.name1,
                [row.participant_two]: row.name2
            },
            lastMessage: row.last_message_text ? {
                text: row.last_message_text,
                senderId: row.last_message_sender,
                timestamp: row.last_message_time
            } : undefined,
            updatedAt: row.last_message_time || row.created_at
        }));
        res.json(chats);
    } catch (error) { handleError(res, error); }
});

app.get('/api/chats/:id/messages', protect, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM messages WHERE chat_id = $1 ORDER BY created_at ASC',
            [req.params.id]
        );
        const messages = result.rows.map(r => ({
            id: r.id,
            chatId: r.chat_id,
            senderId: r.sender_id,
            text: r.text,
            timestamp: r.created_at
        }));
        res.json(messages);
    } catch (error) { handleError(res, error); }
});

app.post('/api/chats/:id/messages', protect, async (req, res) => {
    const { text } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO messages (chat_id, sender_id, text) VALUES ($1, $2, $3) RETURNING *',
            [req.params.id, req.user.id, text]
        );
        const message = result.rows[0];
        
        // Update chat last message
        await pool.query('UPDATE chats SET last_message_id = $1, updated_at = NOW() WHERE id = $2', [message.id, req.params.id]);

        res.status(201).json({
            id: message.id,
            chatId: message.chat_id,
            senderId: message.sender_id,
            text: message.text,
            timestamp: message.created_at
        });
    } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: AI & MISC
// ============================================================================

// Catch-all for undefined API routes
app.use((req, res) => {
    res.status(404).json({ message: `Not Found - ${req.originalUrl}` });
});

// ============================================================================
// VERCEL SERVERLESS EXPORT & LOCAL START
// ============================================================================

// 1. Vercel Serverless Export: The necessary part for deployment
const serverless = require('serverless-http');

// This conditional block is a best practice:
// If running in a Vercel environment, export the handler.
// Otherwise (for local development), start the server with app.listen().

if (process.env.NODE_ENV === 'production' && process.env.VERCEL) {
    // Export the wrapped Express app for Vercel
    module.exports = serverless(app);
} else {
    // Local Development: Start the server using app.listen()
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => {
        console.log(`Server running in ${process.env.NODE_ENV} mode on port ${PORT}`);
    });

    // You can also export the app instance for testing purposes locally
    module.exports = app; 
}