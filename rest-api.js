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
                userId: result.userId
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
                'SELECT * FROM listings WHERE user_id = ? AND listing_status = ? ORDER BY created_at DESC',
                [userId, 'available']
            );

            // Parse pictures JSON for each listing
            const parsedListings = listings.map(listing => ({
                id: listing.id,
                name: listing.listing_name,
                image: JSON.parse(listing.pictures || '[]')[0] || '',
                size: listing.sizing_tags,
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
                image: JSON.parse(listing.pictures || '[]')[0],
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

    /**
     * GET /api/feed/:userId
     * Endpoint to get a random available listing from other users for the feed.
     */
    router.get('/feed/:userId', async (req, res) => {
        const { userId } = req.params;

        try {
            const listing = await db.db.get(
                `SELECT l.*, u.firstname as owner_firstname 
                 FROM listings l
                 JOIN users u ON l.user_id = u.id
                 WHERE l.user_id != ? 
                 AND l.listing_status = 'available'
                 ORDER BY RANDOM()
                 LIMIT 1`,
                [userId]
            );

            if (!listing) {
                return res.status(404).json({
                    error: 'No listings available',
                    message: 'No listings found in the feed at this time.'
                });
            }

            const pictures = JSON.parse(listing.pictures || '[]');
            const colours = listing.colour ? listing.colour.split(',').map(c => c.trim()) : [];
            const clothingTags = listing.article_tags ? listing.article_tags.split(',').map(t => t.trim()) : [];
            const styleTags = listing.style_tags ? listing.style_tags.split(',').map(t => t.trim()) : [];

            const formattedListing = {
                id: listing.id,
                ownerId: listing.user_id,
                ownerName: listing.owner_firstname,
                listingName: listing.listing_name,
                mainPhoto: pictures[0] || '',
                additionalPhotos: pictures.slice(1),
                size: listing.sizing_tags,
                gender: listing.gender_of_sizing,
                location: listing.location || 'Not specified',
                brand: listing.brand || 'Not specified',
                quality: listing.condition,
                colours: colours,
                clothingTags: clothingTags,
                styleTags: styleTags,
                details: listing.listing_description || 'No description provided',
                lookingFor: listing.trade_preferences || 'Open to offers',
                createdAt: listing.created_at
            };

            res.status(200).json(formattedListing);

        } catch (error) {
            console.error('Feed fetch error:', error);
            res.status(500).json({
                error: 'Internal Server Error',
                details: error.message
            });
        }
    });

    /**
     * POST /api/likes
     * Endpoint to send a like/swap offer with selected items.
     */
    router.post('/likes', async (req, res) => {
        const { likerUserId, targetListingId, offeredListingIds, message } = req.body;

        if (!likerUserId || !targetListingId || !offeredListingIds || !Array.isArray(offeredListingIds)) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'likerUserId, targetListingId, and offeredListingIds (array) are required.'
            });
        }

        if (offeredListingIds.length === 0) {
            return res.status(400).json({
                error: 'Invalid offer',
                message: 'At least one item must be offered.'
            });
        }

        try {
            const targetListing = await db.db.get(
                'SELECT id, user_id, listing_name FROM listings WHERE id = ?',
                [targetListingId]
            );

            if (!targetListing) {
                return res.status(404).json({
                    error: 'Listing not found',
                    message: 'The target listing does not exist.'
                });
            }

            const placeholders = offeredListingIds.map(() => '?').join(',');
            const offeredListings = await db.db.all(
                `SELECT id FROM listings WHERE id IN (${placeholders}) AND user_id = ?`,
                [...offeredListingIds, likerUserId]
            );

            if (offeredListings.length !== offeredListingIds.length) {
                return res.status(400).json({
                    error: 'Invalid listings',
                    message: 'Some offered listings do not exist or do not belong to you.'
                });
            }

            const existingLike = await db.db.get(
                `SELECT id FROM likes WHERE liker_user_id = ? AND target_listing_id = ?`,
                [likerUserId, targetListingId]
            );

            if (existingLike) {
                return res.status(409).json({
                    error: 'Like already exists',
                    message: 'You have already liked this listing.'
                });
            }

            const result = await db.db.run(
                `INSERT INTO likes (
                    liker_user_id,
                    owner_user_id,
                    target_listing_id,
                    offered_listing_ids,
                    message,
                    status,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP)`,
                [
                    likerUserId,
                    targetListing.user_id,
                    targetListingId,
                    JSON.stringify(offeredListingIds),
                    message || null
                ]
            );

            res.status(201).json({
                message: 'Like sent successfully!',
                likeId: result.lastID
            });

        } catch (error) {
            console.error('Like creation error:', error);
            res.status(500).json({
                error: 'Internal Server Error',
                details: error.message
            });
        }
    });

    /**
     * GET /api/likes/received/:userId
     * Endpoint to get all likes received by a user on their listings.
     */
    router.get('/likes/received/:userId', async (req, res) => {
        const { userId } = req.params;

        try {
            const likes = await db.db.all(
                `SELECT 
                    l.id as like_id,
                    l.liker_user_id,
                    l.target_listing_id,
                    l.offered_listing_ids,
                    l.message,
                    l.status,
                    l.created_at,
                    u.firstname as liker_name,
                    u.data as liker_data,
                    tl.listing_name as target_listing_name,
                    tl.pictures as target_listing_pictures,
                    tl.sizing_tags,
                    tl.gender_of_sizing,
                    tl.location,
                    tl.brand,
                    tl.condition,
                    tl.colour,
                    tl.article_tags,
                    tl.listing_description,
                    tl.trade_preferences
                FROM likes l
                JOIN users u ON l.liker_user_id = u.id
                JOIN listings tl ON l.target_listing_id = tl.id
                WHERE l.owner_user_id = ? AND l.status = 'pending'
                ORDER BY l.created_at DESC`,
                [userId]
            );

            if (likes.length === 0) {
                return res.status(200).json({
                    likes: [],
                    count: 0
                });
            }

            const formattedLikes = await Promise.all(likes.map(async (like) => {
                const offeredIds = JSON.parse(like.offered_listing_ids || '[]');
                
                const placeholders = offeredIds.map(() => '?').join(',');
                const offeredListings = offeredIds.length > 0 
                    ? await db.db.all(
                        `SELECT id, listing_name, pictures, sizing_tags FROM listings WHERE id IN (${placeholders})`,
                        offeredIds
                    )
                    : [];

                const likerProfile = JSON.parse(like.liker_data || '{}');
                const targetPictures = JSON.parse(like.target_listing_pictures || '[]');
                const colours = like.colour ? like.colour.split(',').map(c => c.trim()) : [];
                const categories = like.article_tags ? like.article_tags.split(',').map(t => t.trim()) : [];

                return {
                    id: like.like_id,
                    likerUserId: like.liker_user_id,
                    userName: like.liker_name,
                    profileImage: likerProfile.profileImage || '',
                    coverImage: targetPictures[0] || '',
                    title: like.target_listing_name,
                    size: like.sizing_tags,
                    brand: like.brand || 'Not specified',
                    condition: like.condition,
                    colors: colours,
                    categories: categories,
                    status: 'Active',
                    details: like.listing_description || 'No description provided',
                    lookingFor: like.trade_preferences || 'Open to offers',
                    location: like.location || 'Not specified',
                    message: like.message,
                    offeredListings: offeredListings.map(ol => ({
                        id: ol.id,
                        name: ol.listing_name,
                        image: JSON.parse(ol.pictures || '[]')[0] || '',
                        size: ol.sizing_tags
                    })),
                    createdAt: like.created_at
                };
            }));

            res.status(200).json({
                likes: formattedLikes,
                count: formattedLikes.length
            });

        } catch (error) {
            console.error('Fetch received likes error:', error);
            res.status(500).json({
                error: 'Internal Server Error',
                details: error.message
            });
        }
    });

    /**
     * PUT /api/likes/:likeId/status
     * Endpoint to update the status of a like (accept/ignore).
     */
    router.put('/likes/:likeId/status', async (req, res) => {
        const { likeId } = req.params;
        const { status } = req.body;

        if (!status || !['accepted', 'ignored'].includes(status)) {
            return res.status(400).json({
                error: 'Invalid status',
                message: 'Status must be either "accepted" or "ignored".'
            });
        }

        try {
            const result = await db.db.run(
                'UPDATE likes SET status = ? WHERE id = ?',
                [status, likeId]
            );

            if (result.changes === 0) {
                return res.status(404).json({
                    error: 'Like not found',
                    message: 'The specified like does not exist.'
                });
            }

            res.status(200).json({
                message: `Like ${status} successfully!`
            });

        } catch (error) {
            console.error('Update like status error:', error);
            res.status(500).json({
                error: 'Internal Server Error',
                details: error.message
            });
        }
    });

    return router;
};