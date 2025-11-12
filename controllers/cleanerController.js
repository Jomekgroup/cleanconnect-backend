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
        // Step 1: Get all cleaners with their profile info and calculated ratings.
        // This is a production-level query that joins users with their cleaner profiles
        // and calculates their average rating and review count from the reviews table.
        // COALESCE is used to ensure a value of 0 is returned if there are no reviews.
        const cleanersQuery = `
            SELECT 
                u.id,
                u.full_name as name,
                u.state,
                u.city,
                u.other_city,
                cp.bio,
                cp.experience_years as experience,
                cp.is_verified,
                cp.subscription_tier,
                cp.charge_hourly,
                cp.charge_daily,
                cp.charge_per_contract,
                cp.charge_per_contract_negotiable,
                cp.profile_photo_url as "photoUrl",
                COALESCE(AVG(r.rating), 0) as rating,
                COUNT(r.id) as reviews
            FROM users u
            JOIN cleaner_profiles cp ON u.id = cp.user_id
            LEFT JOIN reviews r ON u.id = r.cleaner_id
            WHERE u.role = 'cleaner' AND u.is_suspended = false
            GROUP BY u.id, cp.user_id
            ORDER BY rating DESC;
        `;
        const { rows: cleaners } = await pool.query(cleanersQuery);

        // Step 2: Get all services for all cleaners in a single, efficient query.
        const cleanerIds = cleaners.map(c => c.id);
        if (cleanerIds.length === 0) {
            return res.json([]); // Return empty array if no cleaners are found
        }

        const servicesQuery = `
            SELECT cs.cleaner_user_id, s.name 
            FROM cleaner_services cs
            JOIN services s ON cs.service_id = s.id
            WHERE cs.cleaner_user_id = ANY($1::uuid[]);
        `;
        const { rows: services } = await pool.query(servicesQuery, [cleanerIds]);

        // Step 3: Map the services back to each cleaner object. This is more efficient
        // than running a separate query for each cleaner in a loop.
        const cleanersWithServices = cleaners.map(cleaner => {
            const cleanerServices = services
                .filter(s => s.cleaner_user_id === cleaner.id)
                .map(s => s.name);
            return {
                ...cleaner,
                // The frontend 'Cleaner' type expects the field 'serviceTypes'
                serviceTypes: cleanerServices
            };
        });

        res.json(cleanersWithServices);

    } catch (error) {
        next(error); // Pass any database errors to the global error handler
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
        // Fetch cleaner profile
        const cleanerQuery = `
             SELECT u.id, u.full_name as name, u.state, u.city, u.other_city, cp.*
             FROM users u JOIN cleaner_profiles cp ON u.id = cp.user_id
             WHERE u.id = $1 AND u.role = 'cleaner';
        `;
        const cleanerResult = await pool.query(cleanerQuery, [id]);
        if (cleanerResult.rows.length === 0) {
            return res.status(404).json({ message: 'Cleaner not found.' });
        }
        const cleaner = cleanerResult.rows[0];

        // Fetch all reviews for that cleaner
        const reviewsQuery = `SELECT * FROM reviews WHERE cleaner_id = $1 ORDER BY created_at DESC;`;
        const reviewsResult = await pool.query(reviewsQuery, [id]);
        cleaner.reviewsData = reviewsResult.rows;
        
        // Fetch all services for that cleaner
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
        // STEP 1: Initialize the Gemini API SDK securely using the key from .env
        const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

        // STEP 2: Fetch the relevant data for all cleaners to provide context to the AI
        const cleanersDataResult = await pool.query(`
            SELECT u.id, u.full_name, u.state, u.city, cp.bio,
                   (SELECT array_agg(s.name) FROM cleaner_services cs JOIN services s ON cs.service_id = s.id WHERE cs.cleaner_user_id = u.id) as services
            FROM users u
            JOIN cleaner_profiles cp ON u.id = cp.user_id
            WHERE u.role = 'cleaner' AND u.is_suspended = false;
        `);
        const cleanersContext = cleanersDataResult.rows;

        // STEP 3: Engineer a detailed prompt for the AI model
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

        // STEP 4: Call the Gemini API and parse the response
        const response = await ai.models.generateContent({
            model: 'gemini-2.5-flash',
            contents: prompt,
        });
        
        let matchingIds = [];
        try {
            // The AI's response is text. We must parse it into a JavaScript array.
            // A try-catch block is essential in case the AI returns slightly malformed text.
            const cleanedText = response.text.replace(/```json|```/g, '').trim();
            matchingIds = JSON.parse(cleanedText);
        } catch (parseError) {
            console.error("Gemini API response parsing error:", parseError);
            console.error("Original AI response text:", response.text);
            // As a fallback, if the AI fails, we can return an empty array or perform a simple text search.
            // For now, we return an empty array to prevent crashing.
            return res.json({ matchingIds: [] });
        }
        
        // Note: The frontend expects an array of numbers for IDs due to a type inconsistency.
        // The correct implementation returns strings (UUIDs), and the frontend should be updated to match.
        res.json({ matchingIds });

    } catch (error) {
        // This will catch errors from the Gemini API call itself (e.g., invalid key, network issues).
        next(error);
    }
};

module.exports = {
    getAllCleaners,
    getCleanerById,
    aiSearchCleaners
};