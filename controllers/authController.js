// File: controllers/authController.js

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cloudinary = require('../utils/cloudinary');
const { Readable } = require('stream');

// Global PostgreSQL pool from server.js
const pool = global.db;

// -----------------------------
// Generate JWT Token
// -----------------------------
const generateToken = (id, isAdmin) => {
    return jwt.sign({ id, isAdmin }, process.env.JWT_SECRET, {
        expiresIn: '30d',
    });
};

// -----------------------------
// Upload Buffer to Cloudinary
// -----------------------------
// THIS IS THE FIXED VERSION (no duplicate upload_stream, no stream bugs)
const uploadToCloudinary = (fileBuffer, folder = 'cleanconnect') => {
    return new Promise((resolve, reject) => {
        const upload = cloudinary.uploader.upload_stream(
            { folder },
            (error, result) => {
                if (error) return reject(error);
                resolve(result.secure_url);
            }
        );

        const readable = new Readable();
        readable.push(fileBuffer);
        readable.push(null);
        readable.pipe(upload);
    });
};

// -----------------------------
// REGISTER USER
// -----------------------------
const registerUser = async (req, res, next) => {
    const {
        role, email, password, fullName, phoneNumber, gender,
        state, city, otherCity, address,

        // client fields
        clientType, companyName, companyAddress,

        // cleaner fields
        cleanerType, experience, services, bio, nin,
        chargeHourly, chargeDaily, chargePerContract,
        chargePerContractNegotiable,
        bankName, accountNumber,
    } = req.body;

    // files from Multer (matching your form-data fields)
    const { selfie, idDocument } = req.files || {};

    if (!email || !password || !role || !fullName) {
        return res.status(400).json({ message: "Please provide all required fields." });
    }

    const client = await pool.connect();

    try {
        const exists = await client.query(
            "SELECT email FROM users WHERE email = $1",
            [email]
        );

        if (exists.rows.length > 0) {
            return res.status(400).json({ message: "User already exists." });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await client.query("BEGIN");

        // create user
        const newUserQuery = `
            INSERT INTO users (
                email, password_hash, full_name, phone_number,
                gender, state, city, other_city, address, role
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            RETURNING id, email, role, full_name, is_admin;
        `;

        const newUser = (
            await client.query(newUserQuery, [
                email, hashedPassword, fullName, phoneNumber,
                gender, state, city, otherCity, address, role
            ])
        ).rows[0];

        // -----------------------------
        // CLIENT PROFILE
        // -----------------------------
        if (role === "client") {
            await client.query(
                `
                INSERT INTO client_profiles (user_id, client_type, company_name, company_address)
                VALUES ($1,$2,$3,$4)
                `,
                [newUser.id, clientType, companyName, companyAddress]
            );
        }

        // -----------------------------
        // CLEANER PROFILE
        // -----------------------------
        if (role === "cleaner") {
            let selfieUrl = null;
            let idUrl = null;

            // upload files only if provided
            if (selfie && selfie[0]) {
                selfieUrl = await uploadToCloudinary(selfie[0].buffer, "selfies");
            }
            if (idDocument && idDocument[0]) {
                idUrl = await uploadToCloudinary(idDocument[0].buffer, "ids");
            }

            await client.query(
                `
                INSERT INTO cleaner_profiles (
                    user_id, cleaner_type, experience_years, bio, nin,
                    charge_hourly, charge_daily, charge_per_contract,
                    charge_per_contract_negotiable, account_number, bank_name,
                    selfie_url, id_url
                )
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            `,
                [
                    newUser.id,
                    cleanerType,
                    Number(experience) || 0,
                    bio,
                    nin,
                    Number(chargeHourly) || null,
                    Number(chargeDaily) || null,
                    Number(chargePerContract) || null,
                    chargePerContractNegotiable || false,
                    accountNumber,
                    bankName,
                    selfieUrl,
                    idUrl,
                ]
            );

            // -----------------------------
            // CLEANER SERVICES
            // -----------------------------
            if (services && services.length > 0) {
                for (const service of services) {
                    const serviceResult = await client.query(
                        "SELECT id FROM services WHERE name = $1",
                        [service]
                    );

                    if (serviceResult.rows.length > 0) {
                        const serviceId = serviceResult.rows[0].id;

                        await client.query(
                            `
                            INSERT INTO cleaner_services (cleaner_user_id, service_id)
                            VALUES ($1,$2)
                            `,
                            [newUser.id, serviceId]
                        );
                    }
                }
            }
        }

        await client.query("COMMIT");

        const token = generateToken(newUser.id, newUser.is_admin);

        res.status(201).json({
            message: "Registration successful",
            token,
            user: newUser,
        });
    } catch (err) {
        await client.query("ROLLBACK");
        next(err);
    } finally {
        client.release();
    }
};

// -----------------------------
// LOGIN USER
// -----------------------------
const loginUser = async (req, res, next) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query(
            "SELECT * FROM users WHERE email = $1",
            [email]
        );

        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ message: "Invalid login credentials." });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword) {
            return res.status(401).json({ message: "Invalid login credentials." });
        }

        const profileQuery = `
            SELECT 
                u.*,
                cp.cleaner_type, cp.experience_years, cp.bio, cp.selfie_url, cp.id_url,
                clp.client_type, clp.company_name
            FROM users u
            LEFT JOIN cleaner_profiles cp ON cp.user_id = u.id AND u.role='cleaner'
            LEFT JOIN client_profiles clp ON clp.user_id = u.id AND u.role='client'
            WHERE u.id=$1;
        `;

        const fullUser = (await pool.query(profileQuery, [user.id])).rows[0];
        delete fullUser.password_hash;

        const token = generateToken(user.id, user.is_admin);

        res.json({ token, user: fullUser });
    } catch (err) {
        next(err);
    }
};

// -----------------------------
// GET CURRENT USER /me
// -----------------------------
const getMe = async (req, res, next) => {
    try {
        const result = await pool.query(
            `
            SELECT 
                u.*,
                cp.cleaner_type, cp.experience_years, cp.bio, cp.selfie_url, cp.id_url,
                clp.client_type, clp.company_name
            FROM users u
            LEFT JOIN cleaner_profiles cp ON cp.user_id = u.id AND u.role='cleaner'
            LEFT JOIN client_profiles clp ON clp.user_id = u.id AND u.role='client'
            WHERE u.id=$1;
            `,
            [req.user.id]
        );

        const user = result.rows[0];
        if (!user) return res.status(404).json({ message: "User not found" });

        delete user.password_hash;

        res.json(user);
    } catch (err) {
        next(err);
    }
};

module.exports = {
    registerUser,
    loginUser,
    getMe,
};
