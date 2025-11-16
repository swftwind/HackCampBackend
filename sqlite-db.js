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
     * Initializes the database connection and ensures all tables exist.
     */
    async initialize() {
        this.db = await open({
            filename: DB_PATH,
            driver: sqlite3.Database
        });

        await this.db.run('PRAGMA foreign_keys = ON;');
        
        // --- USERS TABLE ---
        await this.db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                firstname TEXT NOT NULL,
                birthday TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data TEXT
            )
        `);

        // --- LISTINGS TABLE ---
        await this.db.run(`
            CREATE TABLE IF NOT EXISTS listings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                listing_name TEXT NOT NULL,
                listing_description TEXT,
                trade_preferences TEXT,
                sizing_tags TEXT NOT NULL,
                gender_of_sizing TEXT NOT NULL,
                location TEXT,
                brand TEXT,
                condition TEXT NOT NULL,
                colour TEXT,
                article_tags TEXT NOT NULL,
                style_tags TEXT,
                pictures TEXT NOT NULL,
                listing_status TEXT DEFAULT 'available',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        console.log('Database initialized. Tables: "users" and "listings" ensured.');
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