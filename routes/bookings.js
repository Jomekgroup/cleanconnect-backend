// File: routes/bookings.js

const express = require('express');
const router = express.Router();
const { createBooking, cancelBooking, approveJobCompletion, submitReview } = require('../controllers/bookingController');
const { protect } = require('../middleware/authMiddleware');

// All booking routes are protected
router.use(protect);

// @route   POST api/bookings
// @desc    Create a new booking
router.post('/', createBooking);

// @route   PUT api/bookings/:id/cancel
// @desc    Cancel a booking
router.put('/:id/cancel', cancelBooking);

// @route   POST api/bookings/:id/complete
// @desc    Client marks a job as complete
router.post('/:id/complete', approveJobCompletion);

// @route   POST api/bookings/:id/review
// @desc    Submit a review for a completed booking
router.post('/:id/review', submitReview);

module.exports = router;