// File: routes/auth.js

const express = require('express');
const router = express.Router();
const { registerUser, loginUser, getMe } = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');
const multer = require('multer');

const storage = multer.memoryStorage();
const upload = multer({ storage });

// ---------------------------
// Routes
// ---------------------------

// Updated to accept all file fields
router.post('/register', upload.fields([
    { name: 'selfie', maxCount: 1 },
    { name: 'governmentId', maxCount: 1 },
    { name: 'profilePhoto', maxCount: 1 },
    { name: 'businessRegDoc', maxCount: 1 }
]), registerUser);

// Login
router.post('/login', loginUser);

// Get current user
router.get('/me', protect, getMe);

module.exports = router;
