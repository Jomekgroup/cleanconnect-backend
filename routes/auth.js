const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const { registerUser, loginUser, getMe } = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');

// ==========================
// Multer Storage
// ==========================
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

// ==========================
// Routes
// ==========================
router.post('/register', upload.fields([{ name: 'selfie' }, { name: 'id' }]), registerUser);
router.post('/login', loginUser);
router.get('/me', protect, getMe);

module.exports = router;
