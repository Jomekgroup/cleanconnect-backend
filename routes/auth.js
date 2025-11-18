// File: routes/auth.js

const express = require('express');
const router = express.Router();
const { registerUser, loginUser, getMe } = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');

// Use the FIXED flexible upload middleware
const { flexibleUpload, handleMulterErrors } = require('../middleware/upload');

// ---------------------------
// Routes
// ---------------------------

// Register with FIXED file upload handling - UPDATED FOR NEW SIGNUPFORM
router.post('/register', 
  (req, res, next) => {
    console.log('🚀 Registration request received');
    console.log('📝 Request content-type:', req.headers['content-type']);
    next();
  },
  flexibleUpload, 
  handleMulterErrors,
  (req, res, next) => {
    console.log('✅ File upload middleware completed successfully');
    console.log('📁 Files available for controller:', req.files ? Object.keys(req.files) : 'None');
    console.log('📝 Form fields received:', Object.keys(req.body));
    next();
  },
  registerUser
);

// Login
router.post('/login', 
  (req, res, next) => {
    console.log('🔐 Login attempt for:', req.body.email);
    next();
  },
  loginUser
);

// Get current user
router.get('/me', protect, getMe);

module.exports = router;