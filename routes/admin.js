// File: routes/admin.js

const express = require('express');
const router = express.Router();
const { 
    getAllUsers, 
    updateUserStatus, 
    deleteUser,
    getPendingConfirmations,
    approveSubscription,
    confirmPayment,
    markBookingPaid
} = require('../controllers/adminController');
const { protect, admin } = require('../middleware/authMiddleware');

// Apply middleware to protect all admin routes
router.use(protect, admin);

// @route   GET api/admin/users
// @desc    Get all clients and cleaners
router.get('/users', getAllUsers);

// @route   PUT api/admin/users/:id/status
// @desc    Suspend or unsuspend a user
router.put('/users/:id/status', updateUserStatus);

// @route   DELETE api/admin/users/:id
// @desc    Delete a user
router.delete('/users/:id', deleteUser);

// @route   GET api/admin/confirmations
// @desc    Get pending subscription and payment confirmations
router.get('/confirmations', getPendingConfirmations);

// @route   POST api/admin/subscriptions/approve
// @desc    Approve a cleaner's subscription
router.post('/subscriptions/approve', approveSubscription);

// @route   POST api/admin/payments/confirm
// @desc    Confirm an Escrow payment receipt
router.post('/payments/confirm', confirmPayment);

// @route   POST api/admin/payments/mark-paid
// @desc    Mark a booking as paid to the cleaner
router.post('/payments/mark-paid', markBookingPaid);

module.exports = router;