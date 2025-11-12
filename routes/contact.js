// File: routes/contact.js

const express = require('express');
const router = express.Router();
const { submitContactForm } = require('../controllers/contactController');

// @route   POST api/contact
// @desc    Submit the contact form
// @access  Public
router.post('/', submitContactForm);

module.exports = router;