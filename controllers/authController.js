// File: controllers/authController.js

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// The global 'db' object is our connection pool from server.js
const pool = global.db;

// --- HELPER FUNCTION ---
// Generate a JSON Web Token (JWT) for authentication
const generateToken = (id, isAdmin) => {
    return jwt.sign({ id, isAdmin }, process.env.JWT_SECRET, {
        expiresIn: '30d',
    });
};

/**
 * @desc    Register a new user (client or cleaner)
 * @route   POST /api/auth/register
 * @access  Public
 */
const registerUser = async (req, res, next) => {
    const {
        role, email, password, fullName, phoneNumber, gender, state, city, otherCity, address,
        clientType, companyName, companyAddress,
        cleanerType, experience, services, bio, nin, chargeHourly, chargeDaily, chargePerContract,
        chargePerContractNegotiable, bankName, accountNumber
        // Note: File uploads (selfie, ID) are URLs here. In a real app, you'd have a separate upload service.
    } = req.body;

    if (!email || !password || !role || !fullName) {
        return res.status(400).json({ message: 'Please provide all required fields.' });
    }

    const client = await pool.connect();
    try {
        const userExists = await client.query("SELECT email FROM users WHERE email = $1", [email]);
        if (userExists.rows.length > 0) {
            return res.status(400).json({ message: 'A user with this email already exists.' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await client.query('BEGIN');

        const newUserQuery = `
            INSERT INTO users (email, password_hash, full_name, phone_number, gender, state, city, other_city, address, role)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, email, role, full_name, is_admin;
        `;
        const newUserResult = await client.query(newUserQuery, [
            email, hashedPassword, fullName, phoneNumber, gender, state, city, otherCity, address, role
        ]);
        const newUser = newUserResult.rows[0];

        if (role === 'client') {
            const clientProfileQuery = `
                INSERT INTO client_profiles (user_id, client_type, company_name, company_address)
                VALUES ($1, $2, $3, $4);
            `;
            await client.query(clientProfileQuery, [newUser.id, clientType, companyName, companyAddress]);
        } else if (role === 'cleaner') {
            const cleanerProfileQuery = `
                INSERT INTO cleaner_profiles (user_id, cleaner_type, experience_years, bio, nin, charge_hourly, charge_daily, charge_per_contract, charge_per_contract_negotiable, account_number, bank_name)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
            `;
            await client.query(cleanerProfileQuery, [
                newUser.id, cleanerType, Number(experience) || 0, bio, nin,
                Number(chargeHourly) || null, Number(chargeDaily) || null, Number(chargePerContract) || null,
                chargePerContractNegotiable || false, accountNumber, bankName
            ]);
            
            // Handle inserting services into the junction table
            if (services && services.length > 0) {
                for (const serviceName of services) {
                    // Find the service ID
                    const serviceResult = await client.query('SELECT id FROM services WHERE name = $1', [serviceName]);
                    if (serviceResult.rows.length > 0) {
                        const serviceId = serviceResult.rows[0].id;
                        await client.query('INSERT INTO cleaner_services (cleaner_user_id, service_id) VALUES ($1, $2)', [newUser.id, serviceId]);
                    }
                }
            }
        }

        await client.query('COMMIT');

        const token = generateToken(newUser.id, newUser.is_admin);
        res.status(201).json({
            token,
            user: newUser
        });

    } catch (error) {
        await client.query('ROLLBACK');
        next(error);
    } finally {
        client.release();
    }
};

/**
 * @desc    Authenticate user & get token
 * @route   POST /api/auth/login
 * @access  Public
 */
const loginUser = async (req, res, next) => {
    const { email, password } = req.body;
    try {
        const query = `SELECT * FROM users WHERE email = $1;`;
        const { rows } = await pool.query(query, [email]);
        const user = rows[0];

        if (user && (await bcrypt.compare(password, user.password_hash))) {
            // Fetch full profile to return to frontend
            const fullProfileQuery = `
                SELECT 
                    u.*, 
                    cp.cleaner_type, cp.experience_years, cp.bio, cp.subscription_tier, cp.subscription_end_date,
                    clp.client_type, clp.company_name
                FROM users u
                LEFT JOIN cleaner_profiles cp ON u.id = cp.user_id AND u.role = 'cleaner'
                LEFT JOIN client_profiles clp ON u.id = clp.user_id AND u.role = 'client'
                WHERE u.id = $1;
            `;
            const profileResult = await pool.query(fullProfileQuery, [user.id]);
            const fullUser = profileResult.rows[0];

            // Fetch booking history and reviews for the user
            const bookingsResult = await pool.query('SELECT * FROM bookings WHERE client_id = $1 OR cleaner_id = $1', [user.id]);
            const reviewsResult = await pool.query('SELECT * FROM reviews WHERE cleaner_id = $1', [user.id]);
            
            fullUser.bookingHistory = bookingsResult.rows;
            fullUser.reviewsData = reviewsResult.rows;

            delete fullUser.password_hash;
            
            const token = generateToken(user.id, user.is_admin);
            res.json({ token, user: fullUser });
        } else {
            res.status(401).json({ message: 'Invalid email or password.' });
        }
    } catch (error) {
        next(error);
    }
};

/**
 * @desc    Get current logged-in user's profile
 * @route   GET /api/auth/me
 * @access  Private
 */
const getMe = async (req, res, next) => {
    if (!req.user || !req.user.id) {
        return res.status(401).json({ message: 'Not authorized, user not found.' });
    }
    try {
        const query = `
            SELECT 
                u.*, 
                cp.cleaner_type, cp.experience_years, cp.bio, cp.subscription_tier, cp.subscription_end_date,
                clp.client_type, clp.company_name
            FROM users u
            LEFT JOIN cleaner_profiles cp ON u.id = cp.user_id AND u.role = 'cleaner'
            LEFT JOIN client_profiles clp ON u.id = clp.user_id AND u.role = 'client'
            WHERE u.id = $1;
        `;
        const { rows } = await pool.query(query, [req.user.id]);
        const user = rows[0];

        if (user) {
            delete user.password_hash;
             // Also attach their bookings and reviews
            const bookingsResult = await pool.query('SELECT * FROM bookings WHERE client_id = $1 OR cleaner_id = $1', [user.id]);
            const reviewsResult = await pool.query('SELECT * FROM reviews WHERE cleaner_id = $1', [user.id]);
            user.bookingHistory = bookingsResult.rows;
            user.reviewsData = reviewsResult.rows;

            res.json(user);
        } else {
            res.status(404).json({ message: 'User not found.' });
        }
    } catch (error) {
        next(error);
    }
};

module.exports = {
    registerUser,
    loginUser,
    getMe,
};