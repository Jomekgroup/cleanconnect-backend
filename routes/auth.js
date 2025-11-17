// File: routes/auth.js

const express = require('express');
const router = express.Router();
const { registerUser, loginUser, getMe } = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');

// Use the shared Cloudinary-powered upload config
const { uploadFields } = require('../middleware/upload');

// ---------------------------
// Routes
// ---------------------------

// Register (supports all expected file fields)
router.post('/register', uploadFields, registerUser);

// Login
router.post('/login', loginUser);

// Get current user
router.get('/me', protect, getMe);

module.exports = router;
