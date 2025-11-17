// File: routes/auth.js

const express = require('express');
const router = express.Router();
const { registerUser, loginUser, getMe } = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');

// Use the enhanced flexible upload middleware
const { flexibleUpload, handleMulterErrors } = require('../middleware/upload');

// ---------------------------
// Routes
// ---------------------------

// Register with enhanced file upload handling
router.post('/register', 
  flexibleUpload, 
  handleMulterErrors, 
  registerUser
);

// Login
router.post('/login', loginUser);

// Get current user
router.get('/me', protect, getMe);

module.exports = router;