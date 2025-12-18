import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Pool } from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname_local = path.dirname(__filename);

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

const generateToken = (id, role, isAdmin, adminRole) => {
  return jwt.sign({ id, role, isAdmin, adminRole }, JWT_SECRET, { expiresIn: '30d' });
};

// --- AUTH FIXES ---

app.post('/api/auth/register', async (req, res) => {
  const { email, password, role, ...rest } = req.body;
  try {
    const normalizedEmail = email.toLowerCase().trim(); // FIX: Lowercase email
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
    if (userExists.rows.length > 0) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, role, full_name, phone_number, state, city, subscription_tier, created_at) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'Free', NOW()) RETURNING *`,
      [normalizedEmail, hashedPassword, role, rest.fullName, rest.phoneNumber, rest.state, rest.city]
    );
    const user = result.rows[0];
    res.status(201).json({ ...user, token: generateToken(user.id, user.role, user.is_admin, user.admin_role) });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const normalizedEmail = email.toLowerCase().trim(); // FIX: Match lowercase email
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
    const user = result.rows[0];

    if (user && (await bcrypt.compare(password, user.password_hash))) {
      const userData = { id: user.id, fullName: user.full_name, email: user.email, role: user.role, isAdmin: user.is_admin };
      res.json({ token: generateToken(user.id, user.role, user.is_admin, user.admin_role), user: userData });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) { res.status(500).json({ message: error.message }); }
});

// --- STATIC FILES FIX ---

app.use('/api/*', (req, res) => {
  res.status(404).json({ message: `API Endpoint Not Found - ${req.originalUrl}` });
});

if (process.env.NODE_ENV === 'production') {
  // Check both 'dist' and '../dist' depending on your folder structure
  const distPath = fs.existsSync(path.join(__dirname_local, 'dist')) 
    ? path.join(__dirname_local, 'dist') 
    : path.join(__dirname_local, '../dist');

  app.use(express.static(distPath));
  app.get('*', (req, res) => res.sendFile(path.join(distPath, 'index.html')));
}

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));