
import express, { Request as ExpressRequest, Response as ExpressResponse, NextFunction, RequestHandler } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import { GoogleGenAI } from '@google/genai';
import { fileURLToPath } from 'url';

// Determine if we are in an ESM environment
const isESM = typeof import.meta !== 'undefined' && import.meta.url;

let __dirname_local = '';
if (isESM) {
    const __filename = fileURLToPath(import.meta.url);
    __dirname_local = path.dirname(__filename);
} else {
    // Fallback for CommonJS environments (ts-node often runs this way by default unless configured otherwise)
    // @ts-ignore
    __dirname_local = typeof __dirname !== 'undefined' ? __dirname : path.resolve();
}

// ============================================================================
// CONFIGURATION
// ============================================================================
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_123';

// Increase payload limit for Base64 image uploads
app.use(express.json({ limit: '50mb' }));
app.use(cors());

// Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // e.g., postgres://user:pass@localhost:5432/cleanconnect
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Gemini AI Client
// The API key MUST be obtained from process.env.API_KEY
const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

// ============================================================================
// TYPES & INTERFACES
// ============================================================================
interface AuthRequest extends ExpressRequest {
  user?: {
    id: string;
    role: string;
    isAdmin: boolean;
    adminRole?: string;
  };
  body: any;
  params: any;
  query: any;
}

// ============================================================================
// UTILITIES
// ============================================================================
const generateToken = (id: string, role: string, isAdmin: boolean, adminRole?: string) => {
  return jwt.sign({ id, role, isAdmin, adminRole }, JWT_SECRET, { expiresIn: '30d' });
};

const sendEmail = async (to: string, subject: string, text: string) => {
  // Mock Email Sender
  if (process.env.NODE_ENV !== 'test') {
    console.log(`\n--- [MOCK EMAIL] ---\nTo: ${to}\nSubject: ${subject}\nBody: ${text}\n--------------------\n`);
  }
};

const handleError = (res: ExpressResponse, error: any, message: string = 'Server Error') => {
  console.error(message, error);
  res.status(500).json({ message: error.message || message });
};

// ============================================================================
// MIDDLEWARE
// ============================================================================
const protect: RequestHandler = (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    try {
      token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, JWT_SECRET) as any;
      (req as AuthRequest).user = decoded;
      next();
    } catch (error) {
      res.status(401).json({ message: 'Not authorized, token failed' });
    }
  } else {
    res.status(401).json({ message: 'Not authorized, no token' });
  }
};

const admin: RequestHandler = (req, res, next) => {
  const authReq = req as AuthRequest;
  if (authReq.user && authReq.user.isAdmin) next();
  else res.status(403).json({ message: 'Admin access required' });
};

// ============================================================================
// ROUTES: AUTH
// ============================================================================
app.post('/api/auth/register', async (req: ExpressRequest, res: ExpressResponse) => {
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
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, 'Free', NOW()) RETURNING *`,
      [email, hashedPassword, role, fullName, phoneNumber, state, city, otherCity, address, clientType, cleanerType, companyName, companyAddress, experience, servicesJson, bio, chargeHourly, chargeDaily, chargePerContract, chargePerContractNegotiable, bankName, accountNumber, profilePhoto, governmentId, businessRegDoc]
    );

    const user = result.rows[0];
    res.status(201).json({
      ...user,
      token: generateToken(user.id, user.role, user.is_admin, user.admin_role)
    });
  } catch (error) { handleError(res, error, 'Registration failed'); }
});

app.post('/api/auth/login', async (req: ExpressRequest, res: ExpressResponse) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (user && (await bcrypt.compare(password, user.password_hash))) {
      if (user.is_suspended) return res.status(403).json({ message: 'Account is suspended.' });
      
      // Normalize DB keys to frontend expectations (camelCase)
      const userData = {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        role: user.role,
        isAdmin: user.is_admin,
        adminRole: user.admin_role,
        profilePhoto: user.profile_photo,
        subscriptionTier: user.subscription_tier,
        // ... other fields loaded in getMe usually
      };
      
      res.json({ token: generateToken(user.id, user.role, user.is_admin, user.admin_role), user: userData });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) { handleError(res, error, 'Login failed'); }
});

// ============================================================================
// ROUTES: ADMIN SEEDING (Dev/Demo)
// ============================================================================
app.get('/api/seed-admins', async (req: ExpressRequest, res: ExpressResponse) => {
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
app.get('/api/users/me', protect, async (req: ExpressRequest, res: ExpressResponse) => {
  const authReq = req as AuthRequest;
  try {
    const result = await pool.query(`
      SELECT 
        u.*, 
        (SELECT json_agg(b.*) FROM bookings b WHERE b.client_id = u.id OR b.cleaner_id = u.id) as booking_history,
        (SELECT json_agg(r.*) FROM reviews r WHERE r.cleaner_id = u.id) as reviews_data
      FROM users u WHERE u.id = $1
    `, [authReq.user!.id]);
    
    const user = result.rows[0];
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Transform DB snake_case to camelCase for frontend
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
      bookingHistory: user.booking_history || [],
      reviewsData: user.reviews_data || [],
      pendingSubscription: user.pending_subscription,
      subscriptionReceipt: user.subscription_receipt ? JSON.parse(user.subscription_receipt) : null,
      isSuspended: user.is_suspended,
      governmentId: user.government_id,
      businessRegDoc: user.business_reg_doc
    };

    res.json(formattedUser);
  } catch (error) { handleError(res, error); }
});

app.put('/api/users/me', protect, async (req: ExpressRequest, res: ExpressResponse) => {
  const authReq = req as AuthRequest;
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
       WHERE id = $19 RETURNING *`,
      [fullName, phoneNumber, address, bio, services ? JSON.stringify(services) : null, experience, chargeHourly, chargeDaily, chargePerContract, profilePhoto, state, city, otherCity, companyName, companyAddress, bankName, accountNumber, chargePerContractNegotiable, authReq.user!.id]
    );
    res.json(result.rows[0]);
  } catch (error) { handleError(res, error, 'Update failed'); }
});

app.get('/api/cleaners', async (req: ExpressRequest, res: ExpressResponse) => {
  try {
    // Advanced query to get aggregated rating and a snippet of recent reviews
    const result = await pool.query(`
      SELECT 
        u.*,
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

    // Format for frontend
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

app.get('/api/cleaners/:id', async (req: ExpressRequest, res: ExpressResponse) => {
    try {
        const result = await pool.query(`
            SELECT 
                u.*,
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
app.post('/api/bookings', protect, async (req: ExpressRequest, res: ExpressResponse) => {
  const authReq = req as AuthRequest;
  const { cleanerId, service, date, amount, totalAmount, paymentMethod } = req.body;
  try {
    const cleanerRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [cleanerId]);
    const cleanerName = cleanerRes.rows[0]?.full_name || 'Cleaner';
    
    const clientRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [authReq.user!.id]);
    const clientName = clientRes.rows[0]?.full_name || 'Client';

    const result = await pool.query(
      `INSERT INTO bookings (
        client_id, cleaner_id, client_name, cleaner_name, service, date, amount, total_amount, payment_method, status, payment_status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'Upcoming', $10, NOW()) RETURNING *`,
      [authReq.user!.id, cleanerId, clientName, cleanerName, service, date, amount, totalAmount, paymentMethod, paymentMethod === 'Direct' ? 'Not Applicable' : 'Pending Payment']
    );

    // camelCase result keys manually or let utility handle it if available. 
    // Here we return row directly, frontend types usually adapted or we should map.
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

    await sendEmail(authReq.user!.id, 'Booking Confirmation', `You booked ${cleanerName} for ${service}.`);
    res.status(201).json(booking);
  } catch (error) { handleError(res, error, 'Booking failed'); }
});

app.post('/api/bookings/:id/cancel', protect, async (req: ExpressRequest, res: ExpressResponse) => {
  try {
    const result = await pool.query("UPDATE bookings SET status = 'Cancelled' WHERE id = $1 RETURNING *", [req.params.id]);
    const b = result.rows[0];
    res.json({ ...b, paymentStatus: b.payment_status, cleanerName: b.cleaner_name, clientName: b.client_name, totalAmount: b.total_amount, cleanerId: b.cleaner_id, clientId: b.client_id });
  } catch (error) { handleError(res, error); }
});

app.post('/api/bookings/:id/complete', protect, async (req: ExpressRequest, res: ExpressResponse) => {
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

app.post('/api/bookings/:id/review', protect, async (req: ExpressRequest, res: ExpressResponse) => {
  const authReq = req as AuthRequest;
  const { rating, timeliness, thoroughness, conduct, comment, cleanerId } = req.body;
  try {
    const clientRes = await pool.query('SELECT full_name FROM users WHERE id = $1', [authReq.user!.id]);
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

app.post('/api/bookings/:id/receipt', protect, async (req: ExpressRequest, res: ExpressResponse) => {
  const { name, dataUrl } = req.body;
  try {
    const receiptJson = JSON.stringify({ name, dataUrl });
    const result = await pool.query(
      "UPDATE bookings SET payment_receipt = $1, payment_status = 'Pending Admin Confirmation' WHERE id = $2 RETURNING *",
      [receiptJson, req.params.id]
    );
    res.json(result.rows[0]); // Returns raw DB row, frontend might need mapping if used directly
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: SUBSCRIPTION
// ============================================================================
app.post('/api/users/subscription/upgrade', protect, async (req: ExpressRequest, res: ExpressResponse) => {
  const authReq = req as AuthRequest;
  const { plan } = req.body;
  try {
    const result = await pool.query(
      "UPDATE users SET pending_subscription = $1 WHERE id = $2 RETURNING *",
      [plan, authReq.user!.id]
    );
    const u = result.rows[0];
    // Return mapped user
    res.json({ ...u, fullName: u.full_name, subscriptionTier: u.subscription_tier, pendingSubscription: u.pending_subscription });
  } catch (error) { handleError(res, error); }
});

app.post('/api/users/subscription/receipt', protect, async (req: ExpressRequest, res: ExpressResponse) => {
  const authReq = req as AuthRequest;
  const { name, dataUrl } = req.body;
  try {
    const receiptJson = JSON.stringify({ name, dataUrl });
    const result = await pool.query(
      "UPDATE users SET subscription_receipt = $1 WHERE id = $2 RETURNING *",
      [receiptJson, authReq.user!.id]
    );
    const u = result.rows[0];
    res.json({ ...u, fullName: u.full_name, subscriptionReceipt: JSON.parse(u.subscription_receipt) });
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: ADMIN
// ============================================================================
app.get('/api/admin/users', protect, admin, async (req: ExpressRequest, res: ExpressResponse) => {
  try {
    const result = await pool.query('SELECT * FROM users ORDER BY created_at DESC');
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

app.patch('/api/admin/users/:id/status', protect, admin, async (req: ExpressRequest, res: ExpressResponse) => {
  const { isSuspended } = req.body;
  try {
    await pool.query('UPDATE users SET is_suspended = $1 WHERE id = $2', [isSuspended, req.params.id]);
    res.json({ message: 'User status updated' });
  } catch (error) { handleError(res, error); }
});

app.delete('/api/admin/users/:id', protect, admin, async (req: ExpressRequest, res: ExpressResponse) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ message: 'User deleted' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/bookings/:id/confirm-payment', protect, admin, async (req: ExpressRequest, res: ExpressResponse) => {
  try {
    await pool.query("UPDATE bookings SET payment_status = 'Confirmed' WHERE id = $1", [req.params.id]);
    res.json({ message: 'Payment confirmed' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/bookings/:id/mark-paid', protect, admin, async (req: ExpressRequest, res: ExpressResponse) => {
  try {
    await pool.query("UPDATE bookings SET payment_status = 'Paid' WHERE id = $1", [req.params.id]);
    res.json({ message: 'Marked as paid' });
  } catch (error) { handleError(res, error); }
});

app.post('/api/admin/users/:id/approve-subscription', protect, admin, async (req: ExpressRequest, res: ExpressResponse) => {
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

app.post('/api/admin/create-admin', protect, admin, async (req: ExpressRequest, res: ExpressResponse) => {
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
     res.status(201).json({ ...u, fullName: u.full_name, isAdmin: u.is_admin, adminRole: u.admin_role });
  } catch (error) { handleError(res, error); }
});

// ============================================================================
// ROUTES: SUPPORT TICKETS
// ============================================================================
app.post('/api/support', protect, async (req: ExpressRequest, res: ExpressResponse) => {
    const authReq = req as AuthRequest;
    const { category, subject, message } = req.body;
    try {
        const result = await pool.query(
            "INSERT INTO support_tickets (user_id, category, subject, message, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING *",
            [authReq.user!.id, category, subject, message]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) { 
        handleError(res, error);
    }
});

app.get('/api/support/my', protect, async (req: ExpressRequest, res: ExpressResponse) => {
    const authReq = req as AuthRequest;
    try {
        const result = await pool.query("SELECT * FROM support_tickets WHERE user_id = $1 ORDER BY created_at DESC", [authReq.user!.id]);
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

app.get('/api/admin/support', protect, admin, async (req: ExpressRequest, res: ExpressResponse) => {
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

app.post('/api/admin/support/:id/resolve', protect, admin, async (req: ExpressRequest, res: ExpressResponse) => {
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
app.post('/api/chats', protect, async (req: ExpressRequest, res: ExpressResponse) => {
    const authReq = req as AuthRequest;
    const { participantId } = req.body;
    const userId = authReq.user!.id;

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
    } catch (error) { handleError(res, error, 'Failed to create chat'); }
});

app.get('/api/chats', protect, async (req: ExpressRequest, res: ExpressResponse) => {
    const authReq = req as AuthRequest;
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
            [authReq.user!.id]
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

app.get('/api/chats/:id/messages', protect, async (req: ExpressRequest, res: ExpressResponse) => {
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

app.post('/api/chats/:id/messages', protect, async (req: ExpressRequest, res: ExpressResponse) => {
    const authReq = req as AuthRequest;
    const { text } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO messages (chat_id, sender_id, text) VALUES ($1, $2, $3) RETURNING *',
            [req.params.id, authReq.user!.id, text]
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
app.post('/api/search/ai', async (req: ExpressRequest, res: ExpressResponse) => {
  const { query } = req.body;
  try {
    const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: `You are a helper for a cleaning service app in Nigeria. 
        Extract key search terms (location, service type, budget) from this user query: "${query}".
        Return ONLY a JSON object with keys: "location" (string), "service" (string), "maxPrice" (number). 
        If info is missing, use null.
        Example: {"location": "Lagos", "service": "Deep Cleaning", "maxPrice": 50000}`
    });
    
    const text = response.text;
    if (!text) {
        throw new Error("No response from AI");
    }
    const cleanJson = text.replace(/```json|```/g, '').trim();
    const criteria = JSON.parse(cleanJson);

    // Build SQL Query based on extracted criteria
    let sql = "SELECT id FROM users WHERE role = 'cleaner' AND is_suspended = false";
    const params: any[] = [];
    let paramIndex = 1;

    if (criteria.location) {
        sql += ` AND (city ILIKE $${paramIndex} OR state ILIKE $${paramIndex} OR other_city ILIKE $${paramIndex})`;
        params.push(`%${criteria.location}%`);
        paramIndex++;
    }
    // Very basic service match, production should use array contains or full text search
    if (criteria.service) {
        sql += ` AND services::text ILIKE $${paramIndex}`;
        params.push(`%${criteria.service}%`);
        paramIndex++;
    }
    if (criteria.maxPrice) {
        sql += ` AND (charge_hourly <= $${paramIndex} OR charge_daily <= $${paramIndex})`;
        params.push(criteria.maxPrice);
        paramIndex++;
    }

    const result = await pool.query(sql, params);
    res.json({ matchingIds: result.rows.map(r => r.id) });

  } catch (error) { 
      console.error(error);
      res.json({ matchingIds: [] });
  }
});

app.post('/api/contact', (req: ExpressRequest, res: ExpressResponse) => {
    console.log('Contact Form:', req.body);
    res.json({ message: 'Message received' });
});

// ============================================================================
// SERVER START
// ============================================================================

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  
  if (!process.env.DATABASE_URL) {
      console.warn("WARNING: DATABASE_URL is not set. Database features will fail.");
  }
  if (!process.env.API_KEY) {
      console.warn("WARNING: API_KEY is not set. AI features will fail.");
  }
});

// Serve static files in production
// Place this AFTER API routes so API requests aren't intercepted by the static handler
if (process.env.NODE_ENV === 'production') {
  // Assuming the build output is in the 'dist' folder at the root level relative to where this script runs
  // If backend/index.ts is run via ts-node, __dirname is .../backend. ../dist is .../dist.
  // If compiled to dist/backend/index.js, adjusting path might be needed. 
  // Standard monorepo or simple deployment usually puts `dist` (frontend) and `backend` as siblings.
  app.use(express.static(path.join(__dirname_local, '../dist')));

  app.get('*', (req: ExpressRequest, res: ExpressResponse) => {
    res.sendFile(path.join(__dirname_local, '../dist/index.html'));
  });
}

app.use((req: ExpressRequest, res: ExpressResponse, next: NextFunction) => {
    res.status(404).json({ message: `Not Found - ${req.originalUrl}` });
});
