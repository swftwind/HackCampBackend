/**
 * Defines the static keys for application secrets.
 * The actual values for these keys should be loaded from the environment 
 * (e.g., process.env.JWT_SECRET) for security.
 */
export class AppSecrets {
    
    // JWT signing key for authenticating users (essential for the login process)
    static JWT_SECRET = 'YOUR_SECURE_JWT_SIGNING_KEY'; 

    // API key for an external service (e.g., Google Maps, payment processor)
    static EXTERNAL_API_KEY = 'YOUR_EXTERNAL_SERVICE_API_KEY';

    // Salt rounds used by bcrypt for password hashing
    static BCRYPT_SALT_ROUNDS = '10'; 

    // Database connection string or specific credentials 
    static DB_CONNECTION_STRING = 'sqlite://hackcamp.db'; 
    
    // Example: Key for encryption/decryption of sensitive data stored in the database
    static ENCRYPTION_KEY = 'A_32_BYTE_ENCRYPTION_KEY'; 

    // Database connection string or specific credentials 
    static DB_PATH = './hackcamp.db'; 

    /**
     * Helper method to get a secret value (encourages using environment variables).
     * @param {string} key - The key name of the secret (e.g., 'JWT_SECRET').
     * @returns {string} The secret value, ideally from process.env.
     */
    static getSecretValue(key) {
        // Look up the actual value from environment variables if available
        const envValue = process.env[key];
        if (envValue) {
            return envValue;
        }

        // Fallback to the hardcoded default (Warning: only for development/testing)
        console.warn(`WARNING: Using hardcoded default value for secret key: ${key}`);
        
        switch(key) {
            case AppSecrets.JWT_SECRET: return 'DEV_SECRET_KEY_DO_NOT_USE_IN_PROD';
            case AppSecrets.EXTERNAL_API_KEY: return 'DEV_API_KEY_123';
            case AppSecrets.BCRYPT_SALT_ROUNDS: return 10;
            default: return 'SECRET_NOT_FOUND';
        }
    }
}