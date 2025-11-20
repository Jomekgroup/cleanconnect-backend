// File: controllers/cleanerController.js

const { GoogleGenAI } = require("@google/genai");

// The global 'db' object is our connection pool from server.js
const pool = global.db;

/**
 * @desc    Get all active cleaners for public listing with ratings and services
 * @route   GET /api/cleaners
 * @access  Public
 */
const getAllCleaners = async (req, res, next) => {
    try {
        // FIXED: Changed 'cleaner_profiles' to 'cleaners'
        // FIXED: Changed alias 'cp' to 'c' to match the new table schema
        const cleanersQuery = `
            SELECT 
                u.id,
                u.full_name as name,
                u.state,
                u.city,
                u.other_city,
                c.bio,
                c.experience_years as experience,
                c.is_verified,
                c.charge_hourly,
                c.charge_daily,
                c.charge_per_contract,
                c.charge_per_contract_negotiable,
                c.profile_photo_url as "photoUrl",
                COALESCE(AVG(r.rating), 0) as rating,
                COUNT(r.id) as reviews
            FROM users u
            JOIN cleaners c ON u.id = c.user_id
            LEFT JOIN reviews r ON u.id = r.cleaner_id
            WHERE u.role = 'cleaner' 
            GROUP BY u.id, c.user_id, c.bio, c.experience_years, c.is_verified, 
                     c.charge_hourly, c.charge_daily, c.charge_per_contract, 
                     c.charge_per_contract_negotiable, c.profile_photo_url
            ORDER BY rating DESC;
        `;
        const { rows: cleaners } = await pool.query(cleanersQuery);

        // Step 2: Get all services for all cleaners in a single, efficient query.
        const cleanerIds = cleaners.map(c => c.id);
        if (cleanerIds.length === 0) {
            return res.json([]); 
        }

        const servicesQuery = `
            SELECT cs.cleaner_user_id, s.name 
            FROM cleaner_services cs
            JOIN services s ON cs.service_id = s.id
            WHERE cs.cleaner_user_id = ANY($1::uuid[]);
        `;
        const { rows: services } = await pool.query(servicesQuery, [cleanerIds]);

        // Step 3: Map the services back to each cleaner object.
        const cleanersWithServices = cleaners.map(cleaner => {
            const cleanerServices = services
                .filter(s => s.cleaner_user_id === cleaner.id)
                .map(s => s.name);
            return {
                ...cleaner,
                serviceTypes: cleanerServices
            };
        });

        res.json(cleanersWithServices);

    } catch (error) {
        next(error); 
    }
};

/**
 * @desc    Get a single cleaner by their user ID with full details and reviews
 * @route   GET /api/cleaners/:id
 * @access  Public
 */
const getCleanerById = async (req, res, next) => {
    try {
        const { id } = req.params;
        // FIXED: Changed 'cleaner_profiles' to 'cleaners'
        const cleanerQuery = `
             SELECT u.id, u.full_name as name, u.state, u.city, u.other_city, c.*
             FROM users u 
             JOIN cleaners c ON u.id = c.user_id
             WHERE u.id = $1 AND u.role = 'cleaner';
        `;
        const cleanerResult = await pool.query(cleanerQuery, [id]);
        if (cleanerResult.rows.length === 0) {
            return res.status(404).json({ message: 'Cleaner not found.' });
        }
        const cleaner = cleanerResult.rows[0];

        // Fetch all reviews
        const reviewsQuery = `SELECT * FROM reviews WHERE cleaner_id = $1 ORDER BY created_at DESC;`;
        const reviewsResult = await pool.query(reviewsQuery, [id]);
        cleaner.reviewsData = reviewsResult.rows;
        
        // Fetch all services
        const servicesQuery = `SELECT s.name FROM services s JOIN cleaner_services cs ON s.id = cs.service_id WHERE cs.cleaner_user_id = $1;`;
        const servicesResult = await pool.query(servicesQuery, [id]);
        cleaner.serviceTypes = servicesResult.rows.map(s => s.name);

        res.json(cleaner);
    } catch (error) {
        next(error);
    }
};

/**
 * @desc    Performs a natural language search for cleaners using the Gemini API.
 * @route   POST /api/cleaners/ai-search
 * @access  Public
 */
const aiSearchCleaners = async (req, res, next) => {
    const { query } = req.body;
    if (!query) {
        return res.status(400).json({ message: 'Search query is required.' });
    }

    try {
        // Initialize Gemini with the new library
        const ai = new GoogleGenAI({ apiKey: process.env.GOOGLE_GENAI_API_KEY });

        // FIXED: Changed 'cleaner_profiles' to 'cleaners'
        const cleanersDataResult = await pool.query(`
            SELECT u.id, u.full_name, u.state, u.city, c.bio,
                   (SELECT array_agg(s.name) FROM cleaner_services cs JOIN services s ON cs.service_id = s.id WHERE cs.cleaner_user_id = u.id) as services
            FROM users u
            JOIN cleaners c ON u.id = c.user_id
            WHERE u.role = 'cleaner';
        `);
        const cleanersContext = cleanersDataResult.rows;

        const prompt = `
            You are a helpful assistant for a cleaning service platform called CleanConnect.
            Based on the following JSON list of available cleaners, find the best matches for the user's query.

            User Query: "${query}"

            Cleaners List (JSON):
            ${JSON.stringify(cleanersContext)}

            Analyze the user's query against each cleaner's name, location (state/city), bio, and services.
            Return ONLY a valid JSON array containing the string IDs of the top 3 best-matching cleaners, ordered from best match to worst.
            Example Response: ["uuid-123", "uuid-456", "uuid-789"]
        `;

        const model = ai.getGenerativeModel({ model: "gemini-1.5-flash" });
        const result = await model.generateContent(prompt);
        const response = await result.response;
        const text = response.text();
        
        let matchingIds = [];
        try {
            const cleanedText = text.replace(/```json|```/g, '').trim();
            matchingIds = JSON.parse(cleanedText);
        } catch (parseError) {
            console.error("Gemini API response parsing error:", parseError);
            return res.json({ matchingIds: [] });
        }
        
        res.json({ matchingIds });

    } catch (error) {
        console.error("AI Search Error:", error);
        res.json({ matchingIds: [] });
    }
};

module.exports = {
    getAllCleaners,
    getCleanerById,
    aiSearchCleaners
};