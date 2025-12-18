const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

// ============================================================================
// CONFIG
// ============================================================================
dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_key_123';

app.use(express.json({ limit: '50mb' }));
app.use(cors());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false
});

const __dirname_local = path.resolve();

// ============================================================================
// UTILITIES
// ============================================================================
const generateToken = (id, role, isAdmin, adminRole) =>
  jwt.sign({ id, role, isAdmin, adminRole }, JWT_SECRET, { expiresIn: '30d' });

const handleError = (res, error, message = 'Server Error') => {
  console.error(message, error);
  res.status(500).json({ message: error.message || message });
};

// ============================================================================
// MIDDLEWARE
// ============================================================================
const protect = (req, res, next) => {
  if (!req.headers.authorization?.startsWith('Bearer')) {
    return res.status(401).json({ message: 'Not authorized, no token' });
  }
  try {
    const token = req.headers.authorization.split(' ')[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Not authorized, token failed' });
  }
};

const admin = (req, res, next) => {
  if (req.user?.isAdmin) return next();
  res.status(403).json({ message: 'Admin access required' });
};

// ============================================================================
// AUTH ROUTES
// ============================================================================

// -------------------- REGISTER --------------------
app.post('/api/auth/register', async (req, res) => {
  try {
    const {
      email, password, role,
      fullName, phoneNumber, state, city, otherCity, address,
      clientType, cleanerType, companyName, companyAddress,
      experience, services, bio,
      chargeHourly, chargeDaily, chargePerContract,
      chargePerContractNegotiable,
      bankName, accountNumber,
      profilePhoto, governmentId, businessRegDoc
    } = req.body;

    if (!email || !password || !role || !fullName) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    const normalizedEmail = email.toLowerCase();
    const exists = await pool.query('SELECT id FROM users WHERE email=$1', [normalizedEmail]);
    if (exists.rows.length) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(`
      INSERT INTO users (
        email, password_hash, role, full_name,
        phone_number, state, city, other_city, address,
        client_type, cleaner_type, company_name, company_address,
        experience, services, bio,
        charge_hourly, charge_daily, charge_per_contract,
        charge_per_contract_negotiable,
        bank_name, account_number,
        profile_photo, government_id, business_reg_doc,
        subscription_tier, created_at
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,
        $10,$11,$12,$13,$14,$15,$16,
        $17,$18,$19,$20,$21,$22,
        $23,$24,$25,'Free',NOW()
      )
    `, [
      normalizedEmail, hashedPassword, role, fullName,
      phoneNumber, state, city, otherCity, address,
      clientType, cleanerType, companyName, companyAddress,
      experience, JSON.stringify(services || []), bio,
      chargeHourly, chargeDaily, chargePerContract,
      chargePerContractNegotiable,
      bankName, accountNumber,
      profilePhoto, governmentId, businessRegDoc
    ]);

    res.status(201).json({ success: true, message: 'Registration successful' });

  } catch (e) { handleError(res, e, 'Registration failed'); }
});

// -------------------- LOGIN --------------------
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const normalizedEmail = email.toLowerCase();

    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [normalizedEmail]);
    const user = rows[0];

    if (!user || !user.password_hash) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    if (user.is_suspended) {
      return res.status(403).json({ message: 'Account suspended' });
    }

    res.json({
      token: generateToken(user.id, user.role, user.is_admin, user.admin_role),
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        role: user.role,
        profilePhoto: user.profile_photo,
        subscriptionTier: user.subscription_tier
      }
    });

  } catch (e) { handleError(res, e, 'Login failed'); }
});

// -------------------- SOCIAL LOGIN --------------------
app.get('/api/auth/social-user', async (req, res) => {
  try {
    const { provider, email, name, photo } = req.query;

    if (!provider || !email) {
      return res.status(400).json({ message: 'Missing social data' });
    }

    const normalizedEmail = email.toLowerCase();
    let { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [normalizedEmail]);
    let user = rows[0];

    if (!user) {
      const insert = await pool.query(`
        INSERT INTO users (
          email, role, full_name, profile_photo,
          social_provider, subscription_tier, created_at
        )
        VALUES ($1,'client',$2,$3,$4,'Free',NOW())
        RETURNING *
      `, [
        normalizedEmail,
        name || 'Social User',
        photo || null,
        provider
      ]);
      user = insert.rows[0];
    }

    res.json({
      token: generateToken(user.id, user.role, user.is_admin, user.admin_role),
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        role: user.role,
        profilePhoto: user.profile_photo,
        subscriptionTier: user.subscription_tier
      }
    });

  } catch (e) { handleError(res, e, 'Social login failed'); }
});

// ============================================================================
// FINAL 404 + STATIC
// ============================================================================
app.use('/api/*', (req, res) =>
  res.status(404).json({ message: `API Not Found - ${req.originalUrl}` })
);

if (process.env.NODE_ENV === 'production') {
  const distPath = path.join(__dirname_local, 'dist');
  if (fs.existsSync(distPath)) {
    app.use(express.static(distPath));
    app.get('*', (_, res) =>
      res.sendFile(path.join(distPath, 'index.html'))
    );
  }
}

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
