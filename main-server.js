import express from 'express';
import cors from 'cors';
import { Database } from './sqlite-db.js';
import { apiRouter } from './rest-api.js';

const PORT = 3000;

const main = async () => {
    const app = express();
    
    // --- 1. Database Initialization ---
    const db = new Database();
    try {
        await db.initialize();
    } catch (error) {
        console.error('FATAL: Failed to initialize database!', error);
        process.exit(1);
    }
    
    // --- 2. Middleware Setup ---
    
    // Enable CORS for frontend requests (Adjust origin in production)
    app.use(cors({ origin: '*' })); 

    // Middleware to parse JSON bodies with increased limit for base64 images
    app.use(express.json({ limit: '50mb' }));
    app.use(express.urlencoded({ limit: '50mb', extended: true }));

    // Middleware to log incoming requests (helpful for debugging)
    app.use((req, res, next) => {
        console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl}`);
        next();
    });

    // --- 3. API Routes ---
    
    // Mount the API router, passing the initialized database instance
    app.use('/api', apiRouter(db));

    // Simple health check route
    app.get('/', (req, res) => {
        res.send('Server is running and healthy.');
    });

    // --- 4. Start Server ---
    app.listen(PORT, () => {
        console.log(`\n✅ Server is running on http://localhost:${PORT}`);
        console.log('Ready to receive registration requests at POST /api/register');
    });
};

main();