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

    /**
     * POST /api/listings
     * Endpoint for creating a new listing.
     */
    router.post('/listings', async (req, res) => {
        const {
            userId,
            listingName,
            listingDescription,
            tradePreferences,
            sizingTags,
            genderOfSizing,
            brand,
            condition,
            colour,
            articleTags,
            styleTags,
            pictures,
            listingStatus
        } = req.body;

        // Validate required fields
        if (!userId || !listingName || !sizingTags || !genderOfSizing || !condition || !articleTags) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'userId, listingName, sizingTags, genderOfSizing, condition, and articleTags are required.'
            });
        }

        // Validate pictures array
        if (!pictures || !Array.isArray(pictures) || pictures.length === 0) {
            return res.status(400).json({
                error: 'Missing pictures',
                message: 'At least one picture is required.'
            });
        }

        try {
            // Verify user exists
            const user = await db.db.get('SELECT id FROM users WHERE id = ?', [userId]);
            if (!user) {
                return res.status(404).json({
                    error: 'User not found',
                    message: 'The specified user does not exist.'
                });
            }

            // Get user's location from their profile
            const userData = await db.db.get('SELECT data FROM users WHERE id = ?', [userId]);
            const userProfile = JSON.parse(userData.data || '{}');
            const location = userProfile.preferredMeetingLocation || 'Not specified';

            // Insert listing into database
            const result = await db.db.run(
                `INSERT INTO listings (
                    user_id, 
                    listing_name, 
                    listing_description, 
                    trade_preferences,
                    sizing_tags,
                    gender_of_sizing,
                    location,
                    brand,
                    condition,
                    colour,
                    article_tags,
                    style_tags,
                    pictures,
                    listing_status,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
                [
                    userId,
                    listingName,
                    listingDescription || null,
                    tradePreferences || null,
                    sizingTags,
                    genderOfSizing,
                    location,
                    brand || null,
                    condition,
                    colour || null,
                    articleTags,
                    styleTags || null,
                    JSON.stringify(pictures),
                    listingStatus || 'available'
                ]
            );

            res.status(201).json({
                message: 'Listing created successfully!',
                listingId: result.lastID
            });

        } catch (error) {
            console.error('Listing creation error:', error);
            res.status(500).json({ 
                error: 'Internal Server Error', 
                details: error.message 
            });
        }
    });

    /**
     * GET /api/listings/user/:userId
     * Endpoint to get all listings for a specific user.
     */
    router.get('/listings/user/:userId', async (req, res) => {
        const { userId } = req.params;

        try {
            const listings = await db.db.all(
                'SELECT * FROM listings WHERE user_id = ? ORDER BY created_at DESC',
                [userId]
            );

            // Parse pictures JSON for each listing
            const parsedListings = listings.map(listing => ({
                ...listing,
                pictures: JSON.parse(listing.pictures || '[]')
            }));

            res.status(200).json({
                listings: parsedListings,
                count: parsedListings.length
            });

        } catch (error) {
            console.error('Fetch listings error:', error);
            res.status(500).json({ 
                error: 'Internal Server Error', 
                details: error.message 
            });
        }
    });

    /**
     * GET /api/profile/:userId
     * Endpoint to get full user profile with listings.
     */
    router.get('/profile/:userId', async (req, res) => {
        const { userId } = req.params;

        try {
            // Get user data
            const user = await db.db.get(
                'SELECT id, email, firstname, birthday, data, created_at FROM users WHERE id = ?',
                [userId]
            );

            if (!user) {
                return res.status(404).json({
                    error: 'User not found',
                    message: 'The specified user does not exist.'
                });
            }

            // Parse user profile data
            const profileData = JSON.parse(user.data || '{}');

            // Get all user listings
            const listings = await db.db.all(
                'SELECT * FROM listings WHERE user_id = ? ORDER BY created_at DESC',
                [userId]
            );

            // Parse pictures for each listing
            const parsedListings = listings.map(listing => ({
                id: listing.id,
                name: listing.listing_name,
                size: listing.sizing_tags,
                image: JSON.parse(listing.pictures || '[]')[0], // First image
                status: listing.listing_status,
                allData: {
                    ...listing,
                    pictures: JSON.parse(listing.pictures || '[]')
                }
            }));

            // Return complete profile
            res.status(200).json({
                userId: user.id,
                firstName: user.firstname,
                email: user.email,
                birthday: user.birthday,
                location: profileData.preferredMeetingLocation || 'Not specified',
                preferredMeetup: profileData.preferredMeetingLocation || 'Not specified',
                bio: profileData.bio || '',
                sizing: profileData.sizing || [],
                style: profileData.style || [],
                profileImage: profileData.profileImage || '',
                coverImage: profileData.coverImage || '',
                listings: parsedListings,
                listingCount: parsedListings.length
            });

        } catch (error) {
            console.error('Profile fetch error:', error);
            res.status(500).json({
                error: 'Internal Server Error',
                details: error.message
            });
        }
    });

    return router;
};