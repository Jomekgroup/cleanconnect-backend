// File: controllers/authController.js
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cloudinary = require('../utils/cloudinary');
const { Readable } = require('stream');

// Global PostgreSQL pool from server.js
const pool = global.db;

// -----------------------------
// Helper: Generate JWT Token
// -----------------------------
const generateToken = (id, isAdmin) => {
    return jwt.sign({ id, isAdmin }, process.env.JWT_SECRET, {
        expiresIn: '30d',
    });
};

// -----------------------------
// Helper: Upload Buffer to Cloudinary
// -----------------------------
const uploadToCloudinary = (fileBuffer, folder = 'cleanconnect') => {
    return new Promise((resolve, reject) => {
        if (!fileBuffer || fileBuffer.length === 0) {
            return reject(new Error('File buffer is empty'));
        }

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
// 1. Validation: Form Data
// -----------------------------
const validateFormData = (data, role, cleanerType, clientType) => {
    const errors = [];
    
    console.log('📝 Validating form data for role:', role);
    
    // --- Common Fields ---
    if (!data.email) errors.push('Email is required');
    if (!data.fullName) errors.push('Full name is required');
    if (!data.phoneNumber) errors.push('Phone number is required');
    if (!data.state) errors.push('State is required');
    if (!data.city) errors.push('City is required');
    if (!data.address) errors.push('Address is required');
    
    // Email Regex
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (data.email && !emailRegex.test(data.email)) errors.push('Invalid email format');
    
    // Phone Regex (10 or 11 digits)
    const phoneRegex = /^[0-9]{10,11}$/;
    if (data.phoneNumber && !phoneRegex.test(data.phoneNumber)) errors.push('Phone number must be 10 or 11 digits');
    
    // "Other" City Validation
    if (data.city === 'Other' && !data.otherCity) {
        errors.push('Please specify your city/town when selecting "Other"');
    }
    
    // --- Client Validation ---
    if (role === 'client') {
        if (!clientType) errors.push('Client type is required');
        if (clientType === 'Company' && (!data.companyName || !data.companyAddress)) {
            errors.push('Company name and address are required for corporate clients');
        }
    }
    
    // --- Cleaner Validation ---
    if (role === 'cleaner') {
        if (!cleanerType) errors.push('Cleaner type is required');
        if (!data.experience && Number(data.experience) !== 0) errors.push('Years of experience is required');
        if (!data.bio) errors.push('Bio is required');
        
        // NIN Validation
        if (!data.nin) errors.push('NIN is required');
        if (data.nin && !/^[0-9]{11}$/.test(data.nin)) errors.push('NIN must be exactly 11 digits');
        
        // Bank Validation
        if (!data.bankName) errors.push('Bank name is required');
        if (!data.accountNumber) errors.push('Account number is required');
        if (data.accountNumber && !/^[0-9]{10}$/.test(data.accountNumber)) errors.push('Account number must be exactly 10 digits');

        // Pricing Validation (At least one price or negotiable contract)
        const hasHourly = Number(data.chargeHourly) > 0;
        const hasDaily = Number(data.chargeDaily) > 0;
        const hasContract = Number(data.chargePerContract) > 0;
        const isNegotiable = data.chargePerContractNegotiable === 'true' || data.chargePerContractNegotiable === true;
        
        if (!hasHourly && !hasDaily && !hasContract && !isNegotiable) {
            errors.push('At least one pricing option (Hourly, Daily, or Contract) must be provided');
        }
        
        // Service Validation
        if (!data.services || (Array.isArray(data.services) && data.services.length === 0)) {
            errors.push('At least one service must be selected');
        }
        
        // Company Cleaner Validation
        if (cleanerType === 'Company' && (!data.companyName || !data.companyAddress)) {
            errors.push('Company name and address are required for company cleaners');
        }
    }
    
    return errors;
};

// -----------------------------
// 2. Validation: Files
// -----------------------------
const validateRequiredFiles = (files, role, cleanerType) => {
    const errors = [];
    
    // 1. Government ID (Required for EVERYONE)
    // Frontend appends as 'idDocument' or 'governmentId'
    const idDoc = files?.idDocument?.[0] || files?.governmentId?.[0];
    if (!idDoc || !idDoc.buffer || idDoc.buffer.length === 0) {
        errors.push('Government ID document is required');
    }
    
    if (role === 'cleaner') {
        // 2. Profile Photo (Required for Cleaners)
        const photo = files?.profilePhoto?.[0];
        if (!photo || !photo.buffer || photo.buffer.length === 0) {
            errors.push('Profile photo is required for cleaners');
        }
        
        // 3. Business Reg (Required for Company Cleaners)
        if (cleanerType === 'Company') {
            const bizReg = files?.businessRegDoc?.[0];
            if (!bizReg || !bizReg.buffer || bizReg.buffer.length === 0) {
                errors.push('Business registration document is required for company cleaners');
            }
        }
    }
    
    return errors;
};

// -----------------------------
// 3. REGISTER USER Controller
// -----------------------------
const registerUser = async (req, res) => {
    console.log('=== REGISTRATION REQUEST STARTED ===');
    
    // 1. Destructure ALL fields from SignupForm
    const {
        role, email, fullName, phoneNumber, gender,
        state, city, otherCity, address, password, // Password comes from frontend default

        // Client specific
        clientType, 
        companyName, companyAddress, // Used for Client Company OR Cleaner Company

        // Cleaner specific
        cleanerType, experience, bio, nin, services,
        chargeHourly, chargeDaily, chargePerContract, chargePerContractNegotiable,
        bankName, accountNumber
    } = req.body;

    const files = req.files || {};

    // 2. Validate Form Data
    const formErrors = validateFormData(req.body, role, cleanerType, clientType);
    if (formErrors.length > 0) {
        return res.status(400).json({ message: `Form Validation: ${formErrors.join(', ')}` });
    }

    // 3. Validate Files
    const fileErrors = validateRequiredFiles(files, role, cleanerType);
    if (fileErrors.length > 0) {
        return res.status(400).json({ message: `File Validation: ${fileErrors.join(', ')}` });
    }

    const client = await pool.connect();

    try {
        // 4. Check existing user
        const exists = await client.query("SELECT email FROM users WHERE email = $1", [email]);
        if (exists.rows.length > 0) {
            return res.status(400).json({ message: "User already exists with this email." });
        }

        // 5. Hash Password
        const salt = await bcrypt.genSalt(10);
        // Use provided password or fallback (Frontend sends 'defaultPassword123!' currently)
        const finalPassword = password || `CleanConnect${Date.now()}`; 
        const hashedPassword = await bcrypt.hash(finalPassword, salt);

        await client.query("BEGIN"); // Start Transaction

        // 6. Insert into USERS table
        // Note: company_name/address stored here if helpful, or in sub-tables. 
        // Based on schema, we usually put personal address in users, company address in sub-profiles.
        const insertUserQuery = `
            INSERT INTO users (
                email, password_hash, full_name, phone_number,
                gender, state, city, other_city, address, role
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, email, role, is_admin;
        `;

        const newUser = (await client.query(insertUserQuery, [
            email, hashedPassword, fullName, phoneNumber,
            gender, state, city, otherCity || null, address, role
        ])).rows[0];

        console.log(`✅ User created: ID ${newUser.id}`);

        // 7. Handle Client Profile
        if (role === 'client') {
            await client.query(`
                INSERT INTO client_profiles (user_id, client_type, company_name, company_address)
                VALUES ($1, $2, $3, $4)
            `, [
                newUser.id, 
                clientType, 
                clientType === 'Company' ? companyName : null, 
                clientType === 'Company' ? companyAddress : null
            ]);
        }

        // 8. Handle Cleaner Profile
        if (role === 'cleaner') {
            // A. Upload Files
            let idUrl = null;
            let photoUrl = null;
            let bizUrl = null;

            try {
                const idFile = files.idDocument?.[0] || files.governmentId?.[0];
                if (idFile) idUrl = await uploadToCloudinary(idFile.buffer, "cleanconnect/ids");
                
                if (files.profilePhoto?.[0]) {
                    photoUrl = await uploadToCloudinary(files.profilePhoto[0].buffer, "cleanconnect/profiles");
                }
                
                if (files.businessRegDoc?.[0]) {
                    bizUrl = await uploadToCloudinary(files.businessRegDoc[0].buffer, "cleanconnect/business_docs");
                }
            } catch (uploadErr) {
                throw new Error(`Image Upload Failed: ${uploadErr.message}`);
            }

            // B. Insert into CLEANERS table
            // Ensure company name/address is saved if they are a company cleaner
            // (Assuming cleaners table has columns for company info, or we rely on the user/bio)
            
            const insertCleanerQuery = `
                INSERT INTO cleaners (
                    user_id, cleaner_type, experience_years, bio, nin,
                    charge_hourly, charge_daily, charge_per_contract, charge_per_contract_negotiable,
                    bank_name, account_number,
                    id_url, profile_photo_url, business_reg_url,
                    company_name, company_address
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            `;

            await client.query(insertCleanerQuery, [
                newUser.id,
                cleanerType,
                Number(experience) || 0,
                bio,
                nin,
                Number(chargeHourly) || null,
                Number(chargeDaily) || null,
                Number(chargePerContract) || null,
                (chargePerContractNegotiable === 'true' || chargePerContractNegotiable === true),
                bankName,
                accountNumber,
                idUrl,
                photoUrl,
                bizUrl,
                cleanerType === 'Company' ? companyName : null,
                cleanerType === 'Company' ? companyAddress : null
            ]);

            // C. Insert Services
            // Frontend sends names like ["Deep Cleaning", "Fumigation"]
            // Backend finds ID for name, then inserts into cleaner_services
            const servicesArray = Array.isArray(services) ? services : [services];
            
            for (const serviceName of servicesArray) {
                if (!serviceName) continue;
                
                // Find Service ID
                const serviceRes = await client.query("SELECT id FROM services WHERE name = $1", [serviceName]);
                
                if (serviceRes.rows.length > 0) {
                    await client.query(
                        "INSERT INTO cleaner_services (cleaner_user_id, service_id) VALUES ($1, $2)",
                        [newUser.id, serviceRes.rows[0].id]
                    );
                } else {
                    console.warn(`⚠️ Service skipped (not found in DB): ${serviceName}`);
                }
            }
        }

        await client.query("COMMIT");
        
        const token = generateToken(newUser.id, newUser.is_admin);
        
        res.status(201).json({
            message: "Registration successful",
            token,
            user: {
                id: newUser.id,
                email: newUser.email,
                role: newUser.role,
                fullName: fullName
            }
        });

    } catch (err) {
        await client.query("ROLLBACK");
        console.error('❌ Registration Error:', err);
        
        // Helper for specific DB errors
        if (err.code === '23505') return res.status(400).json({ message: "Duplicate data (Email/NIN already exists)" });
        if (err.code === '42703') return res.status(500).json({ message: "Database Schema Mismatch (Column missing)" });
        
        res.status(500).json({ message: "Server error during registration: " + err.message });
    } finally {
        client.release();
    }
};

// -----------------------------
// 4. LOGIN USER Controller
// -----------------------------
const loginUser = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
    }

    try {
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        const user = result.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        // Fetch full profile based on role
        let fullProfile = user;
        delete fullProfile.password_hash;

        if (user.role === 'cleaner') {
            const cleanerRes = await pool.query("SELECT * FROM cleaners WHERE user_id = $1", [user.id]);
            fullProfile = { ...fullProfile, ...cleanerRes.rows[0] };
        } else if (user.role === 'client') {
            const clientRes = await pool.query("SELECT * FROM client_profiles WHERE user_id = $1", [user.id]);
            fullProfile = { ...fullProfile, ...clientRes.rows[0] };
        }

        const token = generateToken(user.id, user.is_admin);
        res.json({ token, user: fullProfile });

    } catch (err) {
        console.error('Login Error:', err);
        res.status(500).json({ message: "Server error during login" });
    }
};

// -----------------------------
// 5. GET CURRENT USER (Me)
// -----------------------------
const getMe = async (req, res) => {
    try {
        // Get User Base
        const userRes = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
        if (userRes.rows.length === 0) return res.status(404).json({ message: "User not found" });

        let userData = userRes.rows[0];
        delete userData.password_hash;

        // Append Role Data
        if (userData.role === 'cleaner') {
            const cleanerData = await pool.query(`
                SELECT c.*, 
                       array_agg(s.name) as services 
                FROM cleaners c
                LEFT JOIN cleaner_services cs ON cs.cleaner_user_id = u.id OR cs.cleaner_user_id = c.user_id
                LEFT JOIN services s ON s.id = cs.service_id
                WHERE c.user_id = $1
                GROUP BY c.id
            `, [req.user.id]);
            
            // Note: The join above is simplified; usually better to fetch services separately if complex
            // Falling back to simple fetch for robustness:
            const simpleCleanerData = await pool.query("SELECT * FROM cleaners WHERE user_id = $1", [req.user.id]);
            if (simpleCleanerData.rows.length > 0) {
                userData = { ...userData, ...simpleCleanerData.rows[0] };
            }
        } else if (userData.role === 'client') {
            const clientData = await pool.query("SELECT * FROM client_profiles WHERE user_id = $1", [req.user.id]);
            if (clientData.rows.length > 0) {
                userData = { ...userData, ...clientData.rows[0] };
            }
        }

        res.json(userData);
    } catch (err) {
        console.error('GetMe Error:', err);
        res.status(500).json({ message: "Error fetching profile" });
    }
};

module.exports = { registerUser, loginUser, getMe };