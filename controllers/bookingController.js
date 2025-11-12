// File: controllers/bookingController.js

const pool = global.db;

/**
 * @desc    Create a new booking
 * @route   POST /api/bookings
 * @access  Private
 */
const createBooking = async (req, res, next) => {
    const clientId = req.user.id; // Client is the logged-in user
    const { cleanerId, service, date, amount, totalAmount, paymentMethod } = req.body;

    // Determine initial payment status based on method
    const paymentStatus = paymentMethod === 'Escrow' ? 'Pending Payment' : 'Not Applicable';

    try {
        const query = `
            INSERT INTO bookings (client_id, cleaner_id, service, booking_date, amount, total_amount, payment_method, payment_status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *;
        `;
        const { rows } = await pool.query(query, [clientId, cleanerId, service, date, amount, totalAmount, paymentMethod, paymentStatus]);
        
        res.status(201).json(rows[0]);
    } catch (error) {
        next(error);
    }
};

/**
 * @desc    Cancel a booking
 * @route   PUT /api/bookings/:id/cancel
 * @access  Private (Owner only)
 */
const cancelBooking = async (req, res, next) => {
    const bookingId = req.params.id;
    const userId = req.user.id;

    try {
        const query = `
            UPDATE bookings 
            SET status = 'Cancelled' 
            WHERE id = $1 AND client_id = $2
            RETURNING *;
        `;
        const { rows } = await pool.query(query, [bookingId, userId]);

        if (rows.length === 0) {
            return res.status(404).json({ message: 'Booking not found or you are not authorized to cancel it.' });
        }

        res.json(rows[0]);
    } catch (error) {
        next(error);
    }
};

/**
 * @desc    Client marks a job as complete, triggering payout for Escrow
 * @route   POST /api/bookings/:id/complete
 * @access  Private (Owner only)
 */
const approveJobCompletion = async (req, res, next) => {
    const bookingId = req.params.id;
    const userId = req.user.id;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // First, verify the booking belongs to the user
        const bookingRes = await client.query('SELECT * FROM bookings WHERE id = $1 AND client_id = $2', [bookingId, userId]);
        if (bookingRes.rows.length === 0) {
            return res.status(404).json({ message: 'Booking not found or you are not authorized.' });
        }
        
        const booking = bookingRes.rows[0];
        let paymentStatusUpdate = "";

        // If Escrow, move to 'Pending Payout'. If Direct, the job is just 'Completed'.
        if (booking.payment_method === 'Escrow') {
            paymentStatusUpdate = ", payment_status = 'Pending Payout'";
        }

        const query = `
            UPDATE bookings 
            SET status = 'Completed', job_approved_by_client = true ${paymentStatusUpdate}
            WHERE id = $1
            RETURNING *;
        `;
        const { rows } = await client.query(query, [bookingId]);
        
        await client.query('COMMIT');
        res.json(rows[0]);

    } catch (error) {
        await client.query('ROLLBACK');
        next(error);
    } finally {
        client.release();
    }
};

/**
 * @desc    Submit a review for a completed booking
 * @route   POST /api/bookings/:id/review
 * @access  Private (Owner only)
 */
const submitReview = async (req, res, next) => {
    const bookingId = req.params.id;
    const reviewerId = req.user.id;
    const { cleanerId, rating, timeliness_rating, thoroughness_rating, conduct_rating, comment } = req.body;

    try {
        // Optional: Check if the booking is 'Completed' and belongs to the user before allowing a review.
        const query = `
            INSERT INTO reviews (booking_id, reviewer_id, cleaner_id, rating, timeliness_rating, thoroughness_rating, conduct_rating, comment)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *;
        `;
        const { rows } = await pool.query(query, [bookingId, reviewerId, cleanerId, rating, timeliness_rating, thoroughness_rating, conduct_rating, comment]);
        
        // You could also update the booking to mark that a review was submitted.
        
        res.status(201).json(rows[0]);
    } catch (error) {
        // Catch unique constraint violation if a review for this booking already exists
        if (error.code === '23505') {
            return res.status(400).json({ message: 'A review has already been submitted for this booking.' });
        }
        next(error);
    }
};

module.exports = { createBooking, cancelBooking, approveJobCompletion, submitReview };