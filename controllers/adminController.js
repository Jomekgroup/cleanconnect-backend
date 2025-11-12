// File: controllers/adminController.js

const pool = global.db;

const getAllUsers = async (req, res, next) => {
    try {
        const query = `
            SELECT u.*, cp.*, clp.* 
            FROM users u
            LEFT JOIN cleaner_profiles cp ON u.id = cp.user_id
            LEFT JOIN client_profiles clp ON u.id = clp.user_id
            WHERE u.is_admin = false;
        `;
        const { rows } = await pool.query(query);
        // You would also need to fetch and attach booking/review data for each user here.
        res.json(rows);
    } catch (error) {
        next(error);
    }
};

const updateUserStatus = async (req, res, next) => {
    const { id } = req.params;
    const { isSuspended } = req.body;
    try {
        const query = `UPDATE users SET is_suspended = $1 WHERE id = $2 RETURNING *;`;
        const { rows } = await pool.query(query, [isSuspended, id]);
        res.json(rows[0]);
    } catch (error) {
        next(error);
    }
};

const deleteUser = async (req, res, next) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM users WHERE id = $1', [id]);
        res.status(204).send(); // 204 No Content for successful deletion
    } catch (error) {
        next(error);
    }
};

const getPendingConfirmations = async (req, res, next) => {
    try {
        const paymentsQuery = `
            SELECT * FROM bookings 
            WHERE payment_status = 'Pending Admin Confirmation';
        `;
        const subscriptionsQuery = `
            SELECT u.id, u.full_name, cp.pending_subscription, cp.subscription_receipt_url
            FROM users u
            JOIN cleaner_profiles cp ON u.id = cp.user_id
            WHERE cp.pending_subscription IS NOT NULL;
        `;
        const [payments, subscriptions] = await Promise.all([
            pool.query(paymentsQuery),
            pool.query(subscriptionsQuery)
        ]);
        res.json({
            pendingPayments: payments.rows,
            pendingSubscriptions: subscriptions.rows
        });
    } catch (error) {
        next(error);
    }
};

const approveSubscription = async (req, res, next) => {
    const { userId } = req.body;
    try {
        // This query sets the new tier, calculates a 1-year expiry date, and clears the pending state.
        const query = `
            UPDATE cleaner_profiles
            SET 
                subscription_tier = pending_subscription,
                subscription_end_date = CURRENT_DATE + INTERVAL '1 year',
                pending_subscription = NULL,
                subscription_receipt_url = NULL
            WHERE user_id = $1
            RETURNING *;
        `;
        const { rows } = await pool.query(query, [userId]);
        res.json(rows[0]);
    } catch (error) {
        next(error);
    }
};

const confirmPayment = async (req, res, next) => {
    const { bookingId } = req.body;
    try {
        const query = `
            UPDATE bookings
            SET payment_status = 'Confirmed'
            WHERE id = $1 AND payment_status = 'Pending Admin Confirmation'
            RETURNING *;
        `;
        const { rows } = await pool.query(query, [bookingId]);
        res.json(rows[0]);
    } catch (error) {
        next(error);
    }
};

const markBookingPaid = async (req, res, next) => {
    const { bookingId } = req.body;
    try {
        const query = `
            UPDATE bookings
            SET payment_status = 'Paid'
            WHERE id = $1 AND payment_status = 'Pending Payout'
            RETURNING *;
        `;
        const { rows } = await pool.query(query, [bookingId]);
        res.json(rows[0]);
    } catch (error) {
        next(error);
    }
};

module.exports = { 
    getAllUsers, 
    updateUserStatus, 
    deleteUser,
    getPendingConfirmations,
    approveSubscription,
    confirmPayment,
    markBookingPaid
};