'use strict';

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const cors = require('cors'); // <--- ADD THIS LINE: Imports the cors package

const app = express();
app.use(cors()); // <--- ADD THIS LINE: Enables CORS for all requests from any origin

// Hosting services provide their own port via an environment variable.
// This line tells our app to use that port, or fall back to 3000 for local development.
const port = process.env.PORT || 3000; // <--- CHANGE THIS LINE

// --- CONFIGURATION ---

const ALGORITHM = 'aes-256-gcm';
const MASTER_PASSPHRASE = process.env.MASTER_PASSPHRASE || 'default-insecure-passphrase-change-me!';

if (MASTER_PASSPHRASE === 'default-insecure-passphrase-change-me!') {
    console.warn('\n*** WARNING: YOU ARE USING THE DEFAULT MASTER_PASSPHRASE. ***\n');
}

const SALT_LENGTH = 16;
const IV_LENGTH = 16;
const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 100000;

// --- ENCRYPTION & DECRYPTION FUNCTIONS (Unchanged) ---

function encrypt(text) {
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = crypto.pbkdf2Sync(MASTER_PASSPHRASE, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `${salt.toString('hex')}:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

function decrypt(combinedPayload) {
    const parts = combinedPayload.split(':');
    if (parts.length !== 4) {
        throw new Error('Invalid payload format.');
    }
    const [saltHex, ivHex, authTagHex, encryptedHex] = parts;
    const salt = Buffer.from(saltHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');
    const key = crypto.pbkdf2Sync(MASTER_PASSPHRASE, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// --- EXPRESS ROUTES ---

app.use(express.urlencoded({ extended: true }));

// A simple root route to confirm the backend is running
app.get('/', (req, res) => {
    res.send('AetherCrypt Backend is online and ready for requests.');
});

app.post('/encrypt', (req, res) => {
    const { text } = req.body;
    const encryptedPayload = encrypt(text);
    // Note: The frontend will parse this HTML, so we keep it.
    res.send(`
        <h1>Encrypted Payload:</h1>
        <p>This string contains the salt, IV, authentication tag, and encrypted data.</p>
        <textarea readonly>${encryptedPayload}</textarea>
    `);
});

app.post('/decrypt', (req, res) => {
    const { text } = req.body;
    try {
        const decryptedText = decrypt(text);
        res.send(`
            <h1>Decrypted Text:</h1>
            <p>${decryptedText}</p>
        `);
    } catch (error) {
        console.error('Decryption failed:', error);
        res.status(400).send(`
            <h1>Error Decrypting Text</h1>
            <p>The payload was invalid or has been tampered with. Decryption failed.</p>
        `);
    }
});

// Use the 'port' variable defined at the top
app.listen(port, () => { // <--- CHANGE THIS LINE
  console.log(`AetherCrypt server listening on port ${port}`);
});
