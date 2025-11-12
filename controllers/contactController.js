// File: controllers/contactController.js

const pool = global.db;

/**
 * @desc    Submit the contact form
 * @route   POST /api/contact
 * @access  Public
 */
const submitContactForm = async (req, res, next) => {
    const { topic, name, email, phone, message } = req.body;

    if (!name || !email || !message) {
        return res.status(400).json({ message: 'Name, email, and message are required.' });
    }

    try {
        const query = `
            INSERT INTO contact_messages (topic, name, email, phone, message)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id;
        `;
        await pool.query(query, [topic, name, email, phone, message]);
        
        res.status(201).json({ message: 'Your message has been received! We will get back to you shortly.' });
    } catch (error) {
        next(error);
    }
};

module.exports = { submitContactForm };