import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcryptjs';
import { AppSecrets } from './secrets.js'; 

// Configuration
const DB_PATH = AppSecrets.DB_PATH;

/**
 * Encapsulates all SQLite database operations for the application.
 */
export class Database {
    constructor() {
        this.db = null;
    }

    /**
     * Initializes the database connection and ensures the 'users' table exists.
     */
    async initialize() {
        this.db = await open({
            filename: DB_PATH,
            driver: sqlite3.Database
        });

        await this.db.run('PRAGMA foreign_keys = ON;');
        
        // --- UPDATED TABLE SCHEMA ---
        await this.db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,     -- New unique primary identifier
                password_hash TEXT NOT NULL,
                firstname TEXT NOT NULL,        -- New field
                birthday TEXT,                  -- New field (Stored as TEXT 'YYYY-MM-DD')
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data TEXT                       -- Used for JSON data like preferredMeetingLocation
            )
        `);

        console.log('Database initialized and "users" table ensured.');
    }

    /**
     * Creates a new user in the database.
     * @param {object} userData - Object containing all user registration data.
     * @returns {object} The result of the database insertion.
     */
    async createUser(userData) {
        if (!this.db) {
            throw new Error('Database not initialized.');
        }

        const { email, password, firstname, birthday, preferredMeetingLocation } = userData;

        // Generate a salt and hash the password
        const saltRounds = parseInt(AppSecrets.BCRYPT_SALT_ROUNDS, 10);
        const salt = await bcrypt.genSalt(saltRounds);
        const passwordHash = await bcrypt.hash(password, salt);

        // Store the less structured data (location) as JSON in the 'data' column
        const profileData = JSON.stringify({
            preferredMeetingLocation: preferredMeetingLocation || 'Not specified',
            roles: ['user']
        });

        const result = await this.db.run(
            `INSERT INTO users (email, password_hash, firstname, birthday, data) VALUES (?, ?, ?, ?, ?)`,
            [email, passwordHash, firstname, birthday, profileData]
        );

        // The 'lastID' is the generated user ID (userid).
        return { success: true, userId: result.lastID };
    }
}