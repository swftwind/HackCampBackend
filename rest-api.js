import express from 'express';
import bcrypt from 'bcryptjs';

/**
 * Creates and returns the Express router for the API.
 * @param {Database} db - An instance of the Database class.
 */
export const apiRouter = (db) => {
    const router = express.Router();

    // Middleware to ensure all required fields are present and valid
    const validateRegistration = (req, res, next) => {
        const { email, password, firstname, birthday } = req.body;
        
        // Check for required fields
        if (!email || !password || !firstname) {
            return res.status(400).json({ 
                error: 'Missing fields',
                message: 'Email, password, and first name are required for registration.'
            });
        }
        
        // Basic Email validation
        if (!email.includes('@') || !email.includes('.')) {
            return res.status(400).json({ 
                error: 'Invalid email',
                message: 'Please provide a valid email address.'
            });
        }

        // Password length validation
        if (password.length < 8) {
            return res.status(400).json({ 
                error: 'Invalid password',
                message: 'Password must be at least 8 characters long.'
            });
        }

        // Basic Birthday validation (ensure YYYY-MM-DD format if provided)
        if (birthday && !/^\d{4}-\d{2}-\d{2}$/.test(birthday)) {
             return res.status(400).json({ 
                error: 'Invalid date format',
                message: 'Birthday must be in YYYY-MM-DD format.'
            });
        }
        
        next();
    };

    // Middleware to validate login request
    const validateLogin = (req, res, next) => {
        const { email, password } = req.body;
        
        // Check for required fields
        if (!email || !password) {
            return res.status(400).json({ 
                error: 'Missing fields',
                message: 'Email and password are required.'
            });
        }
        
        next();
    };

    /**
     * POST /api/register
     * Endpoint for user registration.
     */
    router.post('/register', validateRegistration, async (req, res) => {
        // Destructure all expected fields
        const { email, password, firstname, birthday, preferredMeetingLocation } = req.body;
        
        // Compile data object to pass to the DB layer
        const userData = { email, password, firstname, birthday, preferredMeetingLocation };
        
        try {
            // 1. Check if email already exists
            const existingUser = await db.db.get('SELECT id FROM users WHERE email = ?', [email]);
            if (existingUser) {
                return res.status(409).json({ error: 'Conflict', message: 'Email address already registered.' });
            }

            // 2. Process and store the new user
            const result = await db.createUser(userData);

            // 3. Respond to the frontend
            res.status(201).json({ 
                message: 'User registered successfully!', 
                userId: result.userId // This is the auto-generated primary key (userid)
            });

        } catch (error) {
            console.error('Registration error:', error);
            res.status(500).json({ error: 'Internal Server Error', details: error.message });
        }
    });

    /**
     * POST /api/login
     * Endpoint for user login/authentication.
     */
    router.post('/login', validateLogin, async (req, res) => {
        const { email, password } = req.body;
        
        try {
            // 1. Find user by email and get the password hash
            const user = await db.db.get(
                'SELECT id, email, password_hash, firstname FROM users WHERE email = ?', 
                [email]
            );

            // 2. Check if user exists
            if (!user) {
                return res.status(401).json({ 
                    error: 'Authentication failed',
                    message: 'Invalid email or password.' 
                });
            }

            // 3. Verify password using bcrypt to compare with hash
            const isPasswordValid = await bcrypt.compare(password, user.password_hash);
            
            if (!isPasswordValid) {
                return res.status(401).json({ 
                    error: 'Authentication failed',
                    message: 'Invalid email or password.' 
                });
            }

            // 4. Successful login - return user data (excluding password hash)
            res.status(200).json({ 
                message: 'Login successful!',
                userId: user.id,
                email: user.email,
                firstname: user.firstname
            });

        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({ error: 'Internal Server Error', details: error.message });
        }
    });

    return router;
};