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
        
        if (!email || !password || !firstname) {
            return res.status(400).json({ 
                error: 'Missing fields',
                message: 'Email, password, and first name are required for registration.'
            });
        }
        
        if (!email.includes('@') || !email.includes('.')) {
            return res.status(400).json({ 
                error: 'Invalid email',
                message: 'Please provide a valid email address.'
            });
        }

        if (password.length < 8) {
            return res.status(400).json({ 
                error: 'Invalid password',
                message: 'Password must be at least 8 characters long.'
            });
        }

        if (birthday && !/^\d{4}-\d{2}-\d{2}$/.test(birthday)) {
             return res.status(400).json({ 
                error: 'Invalid date format',
                message: 'Birthday must be in YYYY-MM-DD format.'
            });
        }
        
        next();
    };

    const validateLogin = (req, res, next) => {
        const { email, password } = req.body;
        
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
     */
    router.post('/register', validateRegistration, async (req, res) => {
        const { email, password, firstname, birthday, preferredMeetingLocation } = req.body;
        const userData = { email, password, firstname, birthday, preferredMeetingLocation };
        
        try {
            const existingUser = await db.db.get('SELECT id FROM users WHERE email = ?', [email]);
            if (existingUser) {
                return res.status(409).json({ error: 'Conflict', message: 'Email address already registered.' });
            }

            const result = await db.createUser(userData);

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
     */
    router.post('/login', validateLogin, async (req, res) => {
        const { email, password } = req.body;
        
        try {
            const user = await db.db.get(
                'SELECT id, email, password_hash, firstname FROM users WHERE email = ?', 
                [email]
            );

            if (!user) {
                return res.status(401).json({ 
                    error: 'Authentication failed',
                    message: 'Invalid email or password.' 
                });
            }

            const isPasswordValid = await bcrypt.compare(password, user.password_hash);
            
            if (!isPasswordValid) {
                return res.status(401).json({ 
                    error: 'Authentication failed',
                    message: 'Invalid email or password.' 
                });
            }

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
     */
    router.post('/listings', async (req, res) => {
        const {
            userId, listingName, listingDescription, tradePreferences,
            sizingTags, genderOfSizing, brand, condition, colour,
            articleTags, styleTags, pictures, listingStatus
        } = req.body;

        if (!userId || !listingName || !sizingTags || !genderOfSizing || !condition || !articleTags) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'userId, listingName, sizingTags, genderOfSizing, condition, and articleTags are required.'
            });
        }

        if (!pictures || !Array.isArray(pictures) || pictures.length === 0) {
            return res.status(400).json({
                error: 'Missing pictures',
                message: 'At least one picture is required.'
            });
        }

        try {
            const user = await db.db.get('SELECT id FROM users WHERE id = ?', [userId]);
            if (!user) {
                return res.status(404).json({
                    error: 'User not found',
                    message: 'The specified user does not exist.'
                });
            }

            const userData = await db.db.get('SELECT data FROM users WHERE id = ?', [userId]);
            const userProfile = JSON.parse(userData.data || '{}');
            const location = userProfile.preferredMeetingLocation || 'Not specified';

            const result = await db.db.run(
                `INSERT INTO listings (
                    user_id, listing_name, listing_description, trade_preferences,
                    sizing_tags, gender_of_sizing, location, brand, condition, colour,
                    article_tags, style_tags, pictures, listing_status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
                [
                    userId, listingName, listingDescription || null, tradePreferences || null,
                    sizingTags, genderOfSizing, location, brand || null, condition, colour || null,
                    articleTags, styleTags || null, JSON.stringify(pictures), listingStatus || 'available'
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
     */
    router.get('/listings/user/:userId', async (req, res) => {
        const { userId } = req.params;

        try {
            const listings = await db.db.all(
                'SELECT * FROM listings WHERE user_id = ? AND listing_status = ? ORDER BY created_at DESC',
                [userId, 'available']
            );

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
     */
    router.get('/profile/:userId', async (req, res) => {
        const { userId } = req.params;

        try {
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

            const profileData = JSON.parse(user.data || '{}');

            const listings = await db.db.all(
                'SELECT * FROM listings WHERE user_id = ? ORDER BY created_at DESC',
                [userId]
            );

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
                    liker_user_id, owner_user_id, target_listing_id,
                    offered_listing_ids, message, status, created_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP)`,
                [
                    likerUserId, targetListing.user_id, targetListingId,
                    JSON.stringify(offeredListingIds), message || null
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
     */
    router.get('/likes/received/:userId', async (req, res) => {
        const { userId } = req.params;

        try {
            const likes = await db.db.all(
                `SELECT 
                    l.id as like_id, l.liker_user_id, l.target_listing_id,
                    l.offered_listing_ids, l.message, l.status, l.created_at,
                    u.firstname as liker_name, u.data as liker_data,
                    tl.listing_name as target_listing_name, tl.pictures as target_listing_pictures,
                    tl.sizing_tags, tl.gender_of_sizing, tl.location, tl.brand,
                    tl.condition, tl.colour, tl.article_tags,
                    tl.listing_description, tl.trade_preferences
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
                    targetListingId: like.target_listing_id,
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
     * PUT /api/likes/:likeId/accept
     * Accept a like and create a match
     */
    router.put('/likes/:likeId/accept', async (req, res) => {
        const { likeId } = req.params;

        try {
            const like = await db.db.get(
                `SELECT l.*, tl.user_id as owner_id
                 FROM likes l
                 JOIN listings tl ON l.target_listing_id = tl.id
                 WHERE l.id = ? AND l.status = 'pending'`,
                [likeId]
            );

            if (!like) {
                return res.status(404).json({
                    error: 'Like not found',
                    message: 'The specified like does not exist or has already been processed.'
                });
            }

            const offeredListingIds = JSON.parse(like.offered_listing_ids);
            const primaryOfferedListing = offeredListingIds[0];

            // Create match entry
            const matchResult = await db.db.run(
                `INSERT INTO matches (
                    user1_id, user2_id, user1_listing_id, user2_listing_id,
                    like_id, status, created_at
                ) VALUES (?, ?, ?, ?, ?, 'active', CURRENT_TIMESTAMP)`,
                [
                    like.owner_user_id,
                    like.liker_user_id,
                    like.target_listing_id,
                    primaryOfferedListing,
                    like.id
                ]
            );

            // Update like status
            await db.db.run(
                'UPDATE likes SET status = ? WHERE id = ?',
                ['accepted', likeId]
            );

            res.status(200).json({
                message: 'Match created successfully!',
                matchId: matchResult.lastID
            });

        } catch (error) {
            console.error('Accept like error:', error);
            res.status(500).json({
                error: 'Internal Server Error',
                details: error.message
            });
        }
    });

    /**
     * PUT /api/likes/:likeId/ignore
     */
    router.put('/likes/:likeId/ignore', async (req, res) => {
        const { likeId } = req.params;

        try {
            const result = await db.db.run(
                'UPDATE likes SET status = ? WHERE id = ?',
                ['ignored', likeId]
            );

            if (result.changes === 0) {
                return res.status(404).json({
                    error: 'Like not found',
                    message: 'The specified like does not exist.'
                });
            }

            res.status(200).json({
                message: 'Like ignored successfully!'
            });

        } catch (error) {
            console.error('Ignore like error:', error);
            res.status(500).json({
                error: 'Internal Server Error',
                details: error.message
            });
        }
    });

    /**
     * GET /api/matches/:userId
     */
    router.get('/matches/:userId', async (req, res) => {
        const { userId } = req.params;

        try {
            const matches = await db.db.all(
                `SELECT 
                    m.id as match_id,
                    m.user1_id, m.user2_id,
                    m.user1_listing_id, m.user2_listing_id,
                    m.created_at,
                    u1.firstname as user1_name, u1.data as user1_data,
                    u2.firstname as user2_name, u2.data as user2_data,
                    l1.listing_name as user1_listing_name,
                    l1.pictures as user1_listing_pictures,
                    l1.sizing_tags as user1_listing_size,
                    l2.listing_name as user2_listing_name,
                    l2.pictures as user2_listing_pictures,
                    l2.sizing_tags as user2_listing_size
                FROM matches m
                JOIN users u1 ON m.user1_id = u1.id
                JOIN users u2 ON m.user2_id = u2.id
                JOIN listings l1 ON m.user1_listing_id = l1.id
                JOIN listings l2 ON m.user2_listing_id = l2.id
                WHERE (m.user1_id = ? OR m.user2_id = ?) AND m.status = 'active'
                ORDER BY m.created_at DESC`,
                [userId, userId]
            );

            if (matches.length === 0) {
                return res.status(200).json({
                    matches: [],
                    count: 0
                });
            }

            const formattedMatches = await Promise.all(matches.map(async (match) => {
                const isUser1 = match.user1_id === parseInt(userId);
                const otherUserId = isUser1 ? match.user2_id : match.user1_id;
                const otherUserName = isUser1 ? match.user2_name : match.user1_name;
                const otherUserData = JSON.parse(isUser1 ? match.user2_data : match.user1_data);
                const otherUserListingName = isUser1 ? match.user2_listing_name : match.user1_listing_name;
                const otherUserListingPictures = JSON.parse(isUser1 ? match.user2_listing_pictures : match.user1_listing_pictures);
                const otherUserListingSize = isUser1 ? match.user2_listing_size : match.user1_listing_size;
                
                const myListingName = isUser1 ? match.user1_listing_name : match.user2_listing_name;
                const myListingPictures = JSON.parse(isUser1 ? match.user1_listing_pictures : match.user2_listing_pictures);
                const myListingSize = isUser1 ? match.user1_listing_size : match.user2_listing_size;

                // Get last message
                const lastMessage = await db.db.get(
                    `SELECT message_content, sender_id, created_at
                     FROM messages
                     WHERE match_id = ?
                     ORDER BY created_at DESC
                     LIMIT 1`,
                    [match.match_id]
                );

                // Get unread count
                const unreadCount = await db.db.get(
                    `SELECT COUNT(*) as count
                     FROM messages
                     WHERE match_id = ? AND sender_id = ? AND read_at IS NULL`,
                    [match.match_id, otherUserId]
                );

                // Calculate timestamp
                let timestamp = 'New match';
                if (lastMessage) {
                    const messageDate = new Date(lastMessage.created_at);
                    const now = new Date();
                    const diffMs = now - messageDate;
                    const diffMins = Math.floor(diffMs / 60000);
                    const diffHours = Math.floor(diffMs / 3600000);
                    const diffDays = Math.floor(diffMs / 86400000);

                    if (diffMins < 60) {
                        timestamp = `${diffMins}m ago`;
                    } else if (diffHours < 24) {
                        timestamp = `${diffHours}h ago`;
                    } else {
                        timestamp = `${diffDays}d ago`;
                    }
                }

                return {
                    id: match.match_id,
                    itemImage: otherUserListingPictures[0] || '',
                    itemTitle: otherUserListingName,
                    size: otherUserListingSize,
                    userName: otherUserName,
                    userAvatar: otherUserData.profileImage || '',
                    lastMessage: lastMessage ? lastMessage.message_content : 'Start a conversation',
                    timestamp: timestamp,
                    unread: unreadCount.count > 0,
                    myListing: {
                        itemImage: myListingPictures[0] || '',
                        itemTitle: myListingName,
                        size: myListingSize
                    }
                };
            }));

            res.status(200).json({
                matches: formattedMatches,
                count: formattedMatches.length
            });

        } catch (error) {
            console.error('Fetch matches error:', error);
            res.status(500).json({
                error: 'Internal Server Error',
                details: error.message
            });
        }
    });

    /**
     * GET /api/matches/:matchId/messages
     */
    router.get('/matches/:matchId/messages', async (req, res) => {
        const { matchId } = req.params;

        try {
            const messages = await db.db.all(
                `SELECT m.*, u.firstname as sender_name
                 FROM messages m
                 JOIN users u ON m.sender_id = u.id
                 WHERE m.match_id = ?
                 ORDER BY m.created_at ASC`,
                [matchId]
            );

            const formattedMessages = messages.map(msg => ({
                id: msg.id,
                sender: msg.sender_id,
                type: msg.message_type,
                text: msg.message_content,
                image: msg.image_url,
                timestamp: msg.created_at,
                status: msg.read_at ? 'Read' : 'Sent'
            }));

            res.status(200).json({
                messages: formattedMessages
            });

        } catch (error) {
            console.error('Fetch messages error:', error);
            res.status(500).json({
                error: 'Internal Server Error',
                details: error.message
            });
        }
    });

    /**
     * POST /api/matches/:matchId/messages
     */
    router.post('/matches/:matchId/messages', async (req, res) => {
        const { matchId } = req.params;
        const { senderId, messageContent, messageType, imageUrl } = req.body;

        if (!senderId || !messageContent) {
            return res.status(400).json({
                error: 'Missing required fields',
                message: 'senderId and messageContent are required.'
            });
        }

        try {
            const result = await db.db.run(
                `INSERT INTO messages (
                    match_id, sender_id, message_type, message_content,
                    image_url, created_at
                ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
                [matchId, senderId, messageType || 'text', messageContent, imageUrl || null]
            );

            res.status(201).json({
                message: 'Message sent successfully!',
                messageId: result.lastID
            });

        } catch (error) {
            console.error('Send message error:', error);
            res.status(500).json({
                error: 'Internal Server Error',
                details: error.message
            });
        }
    });

    return router;
};