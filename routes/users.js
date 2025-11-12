// File: routes/users.js

const express = require('express');
const router = express.Router();
const { updateUserProfile } = require('../controllers/userController');
const { protect } = require('../middleware/authMiddleware');

// @route   PUT api/users/profile
// @desc    Update user profile
// @access  Private
router.put('/profile', protect, updateUserProfile);

module.exports = router;