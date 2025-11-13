// File: server.js

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();

// ==========================
// 🌍 Flexible CORS Configuration
// ==========================
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true); // Allow Postman, mobile apps, etc.

      const allowedPatterns = [
        /^https?:\/\/localhost:3000$/,                 // Local development
        /^https:\/\/cleanconnect-frontend.*\.vercel\.app$/, // Any Vercel subdomain
      ];

      const isAllowed = allowedPatterns.some((pattern) => pattern.test(origin));
      if (isAllowed) {
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

// ==========================
// 🧠 Debugging Middleware (optional)
// ==========================
app.use((req, res, next) => {
  console.log(`➡️  ${req.method} ${req.originalUrl}`);
  next();
});

// ==========================
// 🧩 Middleware
// ==========================
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
