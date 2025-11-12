// File: server.js

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Toggle SSL based on environment
const isProduction = process.env.NODE_ENV === 'production';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : false
});

pool.connect()
  .then(() => console.log('✅ Connected to PostgreSQL Database'))
  .catch(err => console.error('❌ Database connection error:', err.stack));

global.db = pool;

// API routes
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

// Error handling
app.use((err, req, res, next) => {
  console.error('❌ Server Error:', err.stack);
  res.status(500).json({ message: 'Something went wrong on the server!' });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
