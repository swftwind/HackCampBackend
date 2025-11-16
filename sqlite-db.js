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
        // Open the database
        this.db = await open({
            filename: DB_PATH,
            driver: sqlite3.Database
        });

        // Use PRAGMA foreign_keys = ON; for relational integrity (optional but recommended)
        await this.db.run('PRAGMA foreign_keys = ON;');
        
        // Define the Users Table Schema
        // We use standard columns, not a single JSON blob, as is best practice.
        // The 'data' column is provided in case the user wants to store complex JSON data.
        await this.db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                data TEXT -- For storing arbitrary JSON data if required by the user
            )
        `);

        console.log('Database initialized and "users" table ensured.');
    }

    /**
     * Creates a new user in the database.
     * @param {string} username - The user's chosen username.
     * @param {string} password - The user's raw password (will be hashed).
     * @returns {object} The result of the database insertion.
     */
    async createUser(username, password) {
        if (!this.db) {
            throw new Error('Database not initialized.');
        }

        // Generate a salt and hash the password
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        // Prepare a basic user profile (to demonstrate JSON storage capability)
        const userData = JSON.stringify({
            firstLogin: true,
            roles: ['user']
        });

        const result = await this.db.run(
            `INSERT INTO users (username, password_hash, data) VALUES (?, ?, ?)`,
            [username, passwordHash, userData]
        );

        // The 'lastID' is the ID of the new user, which is useful for the frontend.
        return { success: true, userId: result.lastID };
    }
}