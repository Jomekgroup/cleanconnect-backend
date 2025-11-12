// File: routes/cleaners.js

const express = require('express');
const router = express.Router();
const { getAllCleaners, getCleanerById, aiSearchCleaners } = require('../controllers/cleanerController');

// @route   POST api/cleaners/ai-search
// @desc    Perform a natural language search for cleaners (securely on backend)
// @access  Public
router.post('/ai-search', aiSearchCleaners);

// @route   GET api/cleaners
// @desc    Get all cleaners for public listing
// @access  Public
router.get('/', getAllCleaners);

// @route   GET api/cleaners/:id
// @desc    Get a single cleaner by their user ID
// @access  Public
router.get('/:id', getCleanerById);


module.exports = router;