// File: controllers/userController.js

const pool = global.db;

/**
 * @desc    Update user profile details.
 * @route   PUT /api/users/profile
 * @access  Private
 */
const updateUserProfile = async (req, res, next) => {
    // The user's ID is available from the 'protect' middleware via req.user.id
    const userId = req.user.id;
    const { 
        fullName, phoneNumber, address, gender, bio, experience,
        services, bankName, accountNumber 
        // Add other editable fields here
    } = req.body;

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Update the 'users' table
        const userUpdateQuery = `
            UPDATE users 
            SET full_name = $1, phone_number = $2, address = $3, gender = $4, updated_at = now()
            WHERE id = $5
            RETURNING *;
        `;
        await client.query(userUpdateQuery, [fullName, phoneNumber, address, gender, userId]);
        
        // Find out if the user is a cleaner to update their profile
        const userRoleResult = await client.query('SELECT role FROM users WHERE id = $1', [userId]);
        if (userRoleResult.rows[0].role === 'cleaner') {
            const cleanerProfileUpdateQuery = `
                UPDATE cleaner_profiles
                SET bio = $1, experience_years = $2, bank_name = $3, account_number = $4
                WHERE user_id = $5;
            `;
            await client.query(cleanerProfileUpdateQuery, [bio, experience, bankName, accountNumber, userId]);

            // Here you would also handle updating the cleaner_services junction table
        }
        
        await client.query('COMMIT');

        // Fetch the fully updated user object to send back, similar to the login controller
        const updatedUserQuery = `
            SELECT u.*, cp.*, clp.* FROM users u
            LEFT JOIN cleaner_profiles cp ON u.id = cp.user_id
            LEFT JOIN client_profiles clp ON u.id = clp.user_id
            WHERE u.id = $1;
        `;
        const updatedUserResult = await client.query(updatedUserQuery, [userId]);
        const updatedUser = updatedUserResult.rows[0];
        delete updatedUser.password_hash;

        res.json(updatedUser);

    } catch (error) {
        await client.query('ROLLBACK');
        next(error);
    } finally {
        client.release();
    }
};

module.exports = { updateUserProfile };