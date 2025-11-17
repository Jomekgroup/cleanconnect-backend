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
// Enhanced File Validation - FIXED VERSION
// -----------------------------
const validateRequiredFiles = (files, role, cleanerType) => {
    const errors = [];
    
    console.log('🔍 Validating files:', files ? Object.keys(files) : 'No files');
    
    // Check if selfie exists - support multiple field names and check if file has content
    const selfie = files?.selfie?.[0];
    if (!selfie || !selfie.buffer || selfie.buffer.length === 0) {
        console.log('❌ Selfie validation failed:', selfie ? 'Empty buffer' : 'File missing');
        errors.push('Selfie is required for verification');
    } else {
        console.log('✅ Selfie validation passed');
    }
    
    // Check if ID document exists - support both field names and check content
    const idDocument = files?.idDocument?.[0] || files?.governmentId?.[0];
    if (!idDocument || !idDocument.buffer || idDocument.buffer.length === 0) {
        console.log('❌ ID document validation failed:', idDocument ? 'Empty buffer' : 'File missing');
        errors.push('Government ID document is required for verification');
    } else {
        console.log('✅ ID document validation passed');
    }
    
    // Validate cleaner-specific files
    if (role === 'cleaner') {
        const profilePhoto = files?.profilePhoto?.[0];
        if (!profilePhoto || !profilePhoto.buffer || profilePhoto.buffer.length === 0) {
            console.log('❌ Profile photo validation failed:', profilePhoto ? 'Empty buffer' : 'File missing');
            errors.push('Profile photo is required for cleaners');
        } else {
            console.log('✅ Profile photo validation passed');
        }
        
        // Business registration is required for company cleaners
        if (cleanerType === 'Company') {
            const businessRegDoc = files?.businessRegDoc?.[0];
            if (!businessRegDoc || !businessRegDoc.buffer || businessRegDoc.buffer.length === 0) {
                console.log('❌ Business registration validation failed:', businessRegDoc ? 'Empty buffer' : 'File missing');
                errors.push('Business registration document is required for company cleaners');
            } else {
                console.log('✅ Business registration validation passed');
            }
        }
    }
    
    return errors;
};

// -----------------------------
// Validate Form Data
// -----------------------------
const validateFormData = (data, role, cleanerType, clientType) => {
    const errors = [];
    
    // Basic required fields for all users
    if (!data.email) errors.push('Email is required');
    if (!data.password) errors.push('Password is required');
    if (!data.fullName) errors.push('Full name is required');
    if (!data.phoneNumber) errors.push('Phone number is required');
    if (!data.state) errors.push('State is required');
    if (!data.city) errors.push('City is required');
    if (!data.address) errors.push('Address is required');
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (data.email && !emailRegex.test(data.email)) {
        errors.push('Invalid email format');
    }
    
    // Validate phone number (Nigerian format)
    const phoneRegex = /^[0-9]{10,11}$/;
    if (data.phoneNumber && !phoneRegex.test(data.phoneNumber)) {
        errors.push('Phone number must be 10 or 11 digits');
    }
    
    // Client-specific validation
    if (role === 'client') {
        if (!clientType) errors.push('Client type is required');
        
        if (clientType === 'Company') {
            if (!data.companyName) errors.push('Company name is required for company clients');
            if (!data.companyAddress) errors.push('Company address is required for company clients');
        }
    }
    
    // Cleaner-specific validation
    if (role === 'cleaner') {
        if (!cleanerType) errors.push('Cleaner type is required');
        if (!data.experience && data.experience !== 0) errors.push('Experience is required');
        if (!data.bio) errors.push('Bio is required');
        if (!data.nin) errors.push('NIN is required');
        
        // Validate NIN format (11 digits)
        const ninRegex = /^[0-9]{11}$/;
        if (data.nin && !ninRegex.test(data.nin)) {
            errors.push('NIN must be 11 digits');
        }
        
        // Validate pricing
        const hasPricing = Number(data.chargeHourly) > 0 || 
                          Number(data.chargeDaily) > 0 || 
                          Number(data.chargePerContract) > 0 || 
                          data.chargePerContractNegotiable === 'true' ||
                          data.chargePerContractNegotiable === true;
        if (!hasPricing) {
            errors.push('At least one pricing option is required');
        }
        
        // Validate bank details
        if (!data.bankName) errors.push('Bank name is required');
        if (!data.accountNumber) errors.push('Account number is required');
        
        // Validate account number (10 digits for Nigerian banks)
        const accountRegex = /^[0-9]{10}$/;
        if (data.accountNumber && !accountRegex.test(data.accountNumber)) {
            errors.push('Account number must be 10 digits');
        }
        
        if (cleanerType === 'Company') {
            if (!data.companyName) errors.push('Company name is required for company cleaners');
            if (!data.companyAddress) errors.push('Company address is required for company cleaners');
        }
    }
    
    return errors;
};

// -----------------------------
// REGISTER USER - FIXED VERSION
// -----------------------------
const registerUser = async (req, res, next) => {
    console.log('=== REGISTRATION REQUEST STARTED ===');
    
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

    // Safely handle files
    const files = req.files || {};

    console.log('📝 Form data received:', {
        role,
        email,
        fullName: fullName ? `${fullName.substring(0, 10)}...` : 'missing',
        phoneNumber: phoneNumber ? 'provided' : 'missing',
        clientType,
        cleanerType
    });

    // EXTENSIVE FILE DEBUGGING
    console.log('🔍 FILE ANALYSIS:');
    console.log('req.files exists:', !!req.files);
    
    if (req.files) {
        console.log('📁 Files received:', Object.keys(req.files));
        
        Object.keys(req.files).forEach(fieldName => {
            const fileArray = req.files[fieldName];
            console.log(`   ${fieldName}: ${fileArray.length} file(s)`);
            fileArray.forEach((file, index) => {
                console.log(`     - File ${index + 1}: ${file.originalname} (${file.size} bytes, buffer: ${file.buffer ? file.buffer.length + ' bytes' : 'no buffer'})`);
            });
        });
    } else {
        console.log('❌ NO FILES FOUND - This indicates Multer is not processing files');
    }

    // Validate form data
    const formErrors = validateFormData(req.body, role, cleanerType, clientType);
    if (formErrors.length > 0) {
        console.log('❌ Form validation errors:', formErrors);
        return res.status(400).json({ 
            message: `Form validation failed: ${formErrors.join(', ')}` 
        });
    }

    // Validate required files - BUT with better error handling
    const fileErrors = validateRequiredFiles(files, role, cleanerType);
    if (fileErrors.length > 0) {
        console.log('❌ File validation errors:', fileErrors);
        
        // Provide more helpful error message
        if (!files || Object.keys(files).length === 0) {
            return res.status(400).json({ 
                message: "No files were uploaded. Please check that you've selected all required files and try again." 
            });
        }
        
        return res.status(400).json({ 
            message: `File upload issue: ${fileErrors.join(', ')}. Please ensure all files are selected and under 5MB.` 
        });
    }

    const client = await pool.connect();

    try {
        // Check if user already exists
        console.log('🔍 Checking if user exists...');
        const exists = await client.query(
            "SELECT email FROM users WHERE email = $1",
            [email]
        );

        if (exists.rows.length > 0) {
            console.log('❌ User already exists:', email);
            return res.status(400).json({ message: "User already exists with this email." });
        }

        console.log('✅ User does not exist, proceeding...');

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await client.query("BEGIN");
        console.log('🚀 Transaction started');

        // Create user
        const newUserQuery = `
            INSERT INTO users (
                email, password_hash, full_name, phone_number,
                gender, state, city, other_city, address, role
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, email, role, full_name, is_admin;
        `;

        const newUser = (
            await client.query(newUserQuery, [
                email, hashedPassword, fullName, phoneNumber,
                gender, state, city, otherCity, address, role
            ])
        ).rows[0];

        console.log('✅ User created with ID:', newUser.id);

        // -----------------------------
        // CLIENT PROFILE
        // -----------------------------
        if (role === "client") {
            console.log('👤 Creating client profile...');
            await client.query(
                `
                INSERT INTO client_profiles (user_id, client_type, company_name, company_address)
                VALUES ($1, $2, $3, $4)
                `,
                [newUser.id, clientType, companyName, companyAddress]
            );
            console.log('✅ Client profile created');
        }

        // -----------------------------
        // CLEANER PROFILE
        // -----------------------------
        if (role === "cleaner") {
            console.log('🧹 Creating cleaner profile...');
            
            let selfieUrl = null;
            let idUrl = null;
            let profilePhotoUrl = null;
            let businessRegUrl = null;

            // Upload files to Cloudinary
            try {
                console.log('☁️ Uploading files to Cloudinary...');
                
                if (files.selfie && files.selfie[0]) {
                    console.log('📤 Uploading selfie...');
                    selfieUrl = await uploadToCloudinary(files.selfie[0].buffer, "cleanconnect/selfies");
                    console.log('✅ Selfie uploaded:', selfieUrl ? 'success' : 'failed');
                }

                // Support both field names for ID document
                const idDocument = files.idDocument?.[0] || files.governmentId?.[0];
                if (idDocument) {
                    console.log('📤 Uploading ID document...');
                    idUrl = await uploadToCloudinary(idDocument.buffer, "cleanconnect/ids");
                    console.log('✅ ID document uploaded:', idUrl ? 'success' : 'failed');
                }

                if (files.profilePhoto && files.profilePhoto[0]) {
                    console.log('📤 Uploading profile photo...');
                    profilePhotoUrl = await uploadToCloudinary(files.profilePhoto[0].buffer, "cleanconnect/profiles");
                    console.log('✅ Profile photo uploaded:', profilePhotoUrl ? 'success' : 'failed');
                }

                if (files.businessRegDoc && files.businessRegDoc[0]) {
                    console.log('📤 Uploading business registration...');
                    businessRegUrl = await uploadToCloudinary(files.businessRegDoc[0].buffer, "cleanconnect/business_docs");
                    console.log('✅ Business registration uploaded:', businessRegUrl ? 'success' : 'failed');
                }
            } catch (uploadError) {
                console.error('❌ File upload error:', uploadError);
                await client.query("ROLLBACK");
                return res.status(500).json({ 
                    message: "Error uploading files to storage. Please try again with smaller file sizes." 
                });
            }

            // Insert cleaner profile
            await client.query(
                `
                INSERT INTO cleaner_profiles (
                    user_id, cleaner_type, experience_years, bio, nin,
                    charge_hourly, charge_daily, charge_per_contract,
                    charge_per_contract_negotiable, account_number, bank_name,
                    selfie_url, id_url, profile_photo_url, business_reg_url
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
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
                    chargePerContractNegotiable === 'true' || chargePerContractNegotiable === true,
                    accountNumber,
                    bankName,
                    selfieUrl,
                    idUrl,
                    profilePhotoUrl,
                    businessRegUrl,
                ]
            );
            console.log('✅ Cleaner profile created');

            // -----------------------------
            // CLEANER SERVICES
            // -----------------------------
            if (services && services.length > 0) {
                console.log('🔧 Adding cleaner services...');
                let servicesAdded = 0;
                
                // Handle both array and single service (form data can be either)
                const serviceArray = Array.isArray(services) ? services : [services];
                
                for (const service of serviceArray) {
                    if (!service || service.trim() === '') {
                        console.log('⚠️ Skipping empty service');
                        continue;
                    }
                    
                    const serviceResult = await client.query(
                        "SELECT id FROM services WHERE name = $1",
                        [service.trim()]
                    );

                    if (serviceResult.rows.length > 0) {
                        const serviceId = serviceResult.rows[0].id;

                        await client.query(
                            `
                            INSERT INTO cleaner_services (cleaner_user_id, service_id)
                            VALUES ($1, $2)
                            `,
                            [newUser.id, serviceId]
                        );
                        servicesAdded++;
                        console.log(`✅ Service added: ${service}`);
                    } else {
                        console.warn(`❌ Service not found in database: ${service}`);
                    }
                }
                console.log(`✅ ${servicesAdded} services added total`);
            } else {
                console.log('ℹ️ No services to add');
            }
        }

        await client.query("COMMIT");
        console.log('✅ Transaction committed successfully');

        const token = generateToken(newUser.id, newUser.is_admin);

        console.log('🎉 Registration completed successfully for:', email);
        
        res.status(201).json({
            message: "Registration successful",
            token,
            user: newUser,
        });
        
    } catch (err) {
        await client.query("ROLLBACK");
        console.error('❌ Registration error:', err);
        
        // Provide more specific error messages
        if (err.code === '23505') { // Unique violation
            return res.status(400).json({ message: "User with this email already exists." });
        } else if (err.code === '23502') { // Not null violation
            return res.status(400).json({ message: "Missing required fields." });
        } else if (err.code === '23503') { // Foreign key violation
            return res.status(400).json({ message: "Invalid reference data." });
        } else if (err.code === '22001') { // String data right truncation
            return res.status(400).json({ message: "Data too long for one or more fields." });
        } else if (err.code === '22P02') { // Invalid text representation
            return res.status(400).json({ message: "Invalid data format." });
        }
        
        // Generic error
        res.status(500).json({ 
            message: "Internal server error during registration. Please try again." 
        });
    } finally {
        client.release();
        console.log('🔚 Database connection released');
    }
};

// -----------------------------
// LOGIN USER
// -----------------------------
const loginUser = async (req, res, next) => {
    const { email, password } = req.body;

    console.log('🔐 Login attempt for:', email);

    if (!email || !password) {
        console.log('❌ Login failed: Missing email or password');
        return res.status(400).json({ message: "Email and password are required." });
    }

    try {
        const result = await pool.query(
            "SELECT * FROM users WHERE email = $1",
            [email]
        );

        const user = result.rows[0];

        if (!user) {
            console.log('❌ Login failed: User not found');
            return res.status(401).json({ message: "Invalid login credentials." });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword) {
            console.log('❌ Login failed: Invalid password');
            return res.status(401).json({ message: "Invalid login credentials." });
        }

        const profileQuery = `
            SELECT 
                u.*,
                cp.cleaner_type, cp.experience_years, cp.bio, cp.selfie_url, cp.id_url,
                cp.profile_photo_url, cp.business_reg_url,
                clp.client_type, clp.company_name
            FROM users u
            LEFT JOIN cleaner_profiles cp ON cp.user_id = u.id AND u.role='cleaner'
            LEFT JOIN client_profiles clp ON clp.user_id = u.id AND u.role='client'
            WHERE u.id=$1;
        `;

        const fullUser = (await pool.query(profileQuery, [user.id])).rows[0];
        delete fullUser.password_hash;

        const token = generateToken(user.id, user.is_admin);

        console.log('✅ Login successful for:', email);
        res.json({ token, user: fullUser });
    } catch (err) {
        console.error('❌ Login error:', err);
        next(err);
    }
};

// -----------------------------
// GET CURRENT USER /me
// -----------------------------
const getMe = async (req, res, next) => {
    try {
        console.log('👤 Fetching user profile for ID:', req.user.id);
        
        const result = await pool.query(
            `
            SELECT 
                u.*,
                cp.cleaner_type, cp.experience_years, cp.bio, cp.selfie_url, cp.id_url,
                cp.profile_photo_url, cp.business_reg_url,
                clp.client_type, clp.company_name
            FROM users u
            LEFT JOIN cleaner_profiles cp ON cp.user_id = u.id AND u.role='cleaner'
            LEFT JOIN client_profiles clp ON clp.user_id = u.id AND u.role='client'
            WHERE u.id=$1;
            `,
            [req.user.id]
        );

        const user = result.rows[0];
        if (!user) {
            console.log('❌ User not found for ID:', req.user.id);
            return res.status(404).json({ message: "User not found" });
        }

        delete user.password_hash;

        console.log('✅ User profile fetched successfully');
        res.json(user);
    } catch (err) {
        console.error('❌ GetMe error:', err);
        next(err);
    }
};

module.exports = {
    registerUser,
    loginUser,
    getMe,
};