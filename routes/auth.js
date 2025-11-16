// File: routes/auth.js

const express = require('express');
const router = express.Router();
const { registerUser, loginUser, getMe } = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');
const multer = require('multer');

// Multer configuration for memory storage (buffer)
const storage = multer.memoryStorage();
const upload = multer({ storage });

// ---------------------------
// Routes
// ---------------------------

// @route   POST /api/auth/register
// @desc    Register a new user (client or cleaner) with optional file uploads
// @access  Public
// 'selfie' and 'idDocument' are the field names expected in the frontend FormData
router.post('/register', upload.fields([
    { name: 'selfie', maxCount: 1 },
    { name: 'idDocument', maxCount: 1 }
]), registerUser);

// @route   POST /api/auth/login
// @desc    Authenticate user & get token
// @access  Public
router.post('/login', loginUser);

// @route   GET /api/auth/me
// @desc    Get current logged-in user data
// @access  Private
router.get('/me', protect, getMe);

module.exports = router;
