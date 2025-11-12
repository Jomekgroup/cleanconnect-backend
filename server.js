// File: server.js

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

// Initialize express app
const app = express();

// ==========================
// 🌍 CORS Configuration
// ==========================
const allowedOrigins = [
  'http://localhost:3000',                       // Local development
  'https://cleanconnect-frontend.vercel.app',    // Your Vercel frontend domain
];

// Configure CORS dynamically
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true); // allow requests with no origin (Postman, mobile apps)
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      } else {
        console.warn('❌ CORS blocked for origin:', origin);
        return callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// Enable JSON parsing
app.use(express.json({ limit: '10mb' }));

// ==========================
// 💾 PostgreSQL Connection
// ==========================
const isProduction = process.env.NODE_ENV === 'production';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : false,
});

pool.connect()
  .then(() => console.log('✅ Connected to PostgreSQL Database'))
  .catch((err) => console.error('❌ Database connection error:', err.stack));

global.db = pool;

// ==========================
// 📦 API Routes
// ==========================
app.use('/api/auth', require('./routes/auth'));
app.use('/api/users', require('./routes/users'));
app.use('/api/cleaners', require('./routes/cleaners'));
app.use('/api/bookings', require('./routes/bookings'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api/contact', require('./routes/contact'));

// ==========================
// 🏠 Root Route
// ==========================
app.get('/', (req, res) => {
  res.send('🌍 CleanConnect Backend is Running Successfully 🚀');
});

// ==========================
// ⚠️ Global Error Handling
// ==========================
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err.message);
  res.status(500).json({
    success: false,
    message: err.message || 'Something went wrong on the server!',
  });
});

// ==========================
// 🚀 Start Server
// ==========================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
