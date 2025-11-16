// File: routes/auth.js

const express = require('express');
const router = express.Router();
const { registerUser, loginUser, getMe } = require('../controllers/authController');
const { protect } = require('../middleware/authMiddleware');
const multer = require('multer');

// Memory storage for Cloudinary uploads
const storage = multer.memoryStorage();
const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

// These MUST MATCH your SignupForm
router.post(
    '/register',
    upload.fields([
        { name: 'selfie', maxCount: 1 },
        { name: 'idDocument', maxCount: 1 }
    ]),
    registerUser
);

router.post('/login', loginUser);

router.get('/me', protect, getMe);

module.exports = router;
