// File: server.js

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();

// ==========================
// CORS Configuration
// ==========================
const allowedOrigins = [
  'http://localhost:3000', // local React dev
  'https://your-vercel-frontend.vercel.app', // replace with your actual Vercel frontend URL
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS policy: ${origin} not allowed`));
    }
  },
  credentials: true, // allows cookies and auth headers
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

// ==========================
// PostgreSQL Connection
// ==========================
const isProduction = process.env.NODE_ENV === 'production';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : false,
});

pool.connect()
  .then(() => console.log('✅ Connected to PostgreSQL Database'))
  .catch(err => console.error('❌ Database connection error:', err.stack));

global.db = pool;

// ==========================
// API Routes
// ==========================
app.use('/api/auth', require('./routes/auth'));
app.use('/api/users', require('./routes/users'));
app.use('/api/cleaners', require('./routes/cleaners'));
app.use('/api/bookings', require('./routes/bookings'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api/contact', require('./routes/contact'));

// Root route
app.get('/', (req, res) => {
  res.send('🌍 CleanConnect Backend is Running Successfully 🚀');
});

// ==========================
// Error Handling Middleware
// ==========================
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err.stack);
  if (err.message.includes('CORS')) {
    return res.status(403).json({ message: err.message });
  }
  res.status(500).json({ message: 'Something went wrong on the server!' });
});

// ==========================
// Start Server
// ==========================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
