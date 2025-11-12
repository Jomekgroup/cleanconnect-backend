// File: middleware/authMiddleware.js

const jwt = require('jsonwebtoken');
// const pool = require('../config/db');

const protect = async (req, res, next) => {
    let token;

    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        try {
            // Get token from header
            token = req.headers.authorization.split(' ')[1];

            // Verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            // --- DATABASE LOGIC ---
            // Get user from the token's ID and attach to request object
            // req.user = await pool.query("SELECT id, is_admin FROM users WHERE id = $1", [decoded.id]).rows[0];
            // delete req.user.password_hash; // Don't include password hash

            // --- MOCK LOGIC ---
            req.user = { id: decoded.id, is_admin: decoded.id === 'admin-001' }; // Mock user object

            next();
        } catch (error) {
            console.error(error);
            res.status(401).json({ message: 'Not authorized, token failed' });
        }
    }

    if (!token) {
        res.status(401).json({ message: 'Not authorized, no token' });
    }
};

const admin = (req, res, next) => {
    if (req.user && req.user.is_admin) {
        next();
    } else {
        res.status(401).json({ message: 'Not authorized as an admin' });
    }
};

module.exports = { protect, admin };