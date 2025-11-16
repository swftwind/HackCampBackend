import express from 'express';

/**
 * Creates and returns the Express router for the API.
 * @param {Database} db - An instance of the Database class.
 */
export const apiRouter = (db) => {
    const router = express.Router();

    // Middleware to ensure all required fields are present
    const validateRegistration = (req, res, next) => {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ 
                error: 'Missing fields',
                message: 'Username and password are required for registration.'
            });
        }
        if (password.length < 8) {
            return res.status(400).json({ 
                error: 'Invalid password',
                message: 'Password must be at least 8 characters long.'
            });
        }
        next();
    };

    /**
     * POST /api/register
     * Endpoint for user registration.
     */
    router.post('/register', validateRegistration, async (req, res) => {
        const { username, password } = req.body;
        
        try {
            // 1. Check if username already exists (Optional, but good practice. The UNIQUE constraint in SQL will also catch this.)
            const existingUser = await db.db.get('SELECT id FROM users WHERE username = ?', [username]);
            if (existingUser) {
                return res.status(409).json({ error: 'Conflict', message: 'Username already taken.' });
            }

            // 2. Process and store the new user
            const result = await db.createUser(username, password);

            // 3. Respond to the frontend
            res.status(201).json({ 
                message: 'User registered successfully!', 
                userId: result.userId 
            });

        } catch (error) {
            console.error('Registration error:', error);
            // In a real app, you might check error type (e.g., SQL UNIQUE constraint violation)
            res.status(500).json({ error: 'Internal Server Error', details: error.message });
        }
    });

    return router;
};