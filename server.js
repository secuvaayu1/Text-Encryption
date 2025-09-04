'use strict';

const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
const port = 3000;

// --- CONFIGURATION ---

// 1. THE ALGORITHM: Use the modern, authenticated AES-GCM standard.
const ALGORITHM = 'aes-256-gcm';

// 2. THE MASTER SECRET: Use a passphrase from an environment variable.
// This is more flexible than a fixed 32-char key.
// For production, set this with: export MASTER_PASSPHRASE="a very long and secure password"
const MASTER_PASSPHRASE = process.env.MASTER_PASSPHRASE || 'default-insecure-passphrase-change-me!';

// Warn the user if they are using the default, insecure passphrase.
if (MASTER_PASSPHRASE === 'default-insecure-passphrase-change-me!') {
    console.warn('\n*** WARNING: YOU ARE USING THE DEFAULT MASTER_PASSPHRASE. ***');
    console.warn('*** This is insecure and should NOT be used in production. ***');
    console.warn('*** Set a secure environment variable for MASTER_PASSPHRASE. ***\n');
}

// 3. PBKDF2 a key derivation settings. These make it slow for attackers.
const SALT_LENGTH = 16; // A new salt is generated for each encryption.
const IV_LENGTH = 16;   // A new IV is generated for each encryption.
const KEY_LENGTH = 32;  // 32 bytes for AES-256.
const PBKDF2_ITERATIONS = 100000; // A high number of iterations.

/**
 * Encrypts text using a derived key and authenticated encryption.
 * @param {string} text - The plaintext to encrypt.
 * @returns {string} - A single string containing all parts needed for decryption, separated by colons.
 */
function encrypt(text) {
    // a. Generate a new, random salt for every encryption. This is critical.
    const salt = crypto.randomBytes(SALT_LENGTH);

    // b. Derive a strong encryption key from the master passphrase and the salt.
    const key = crypto.pbkdf2Sync(MASTER_PASSPHRASE, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');

    // c. Generate a new, random Initialization Vector (IV).
    const iv = crypto.randomBytes(IV_LENGTH);

    // d. Create the AES-GCM cipher.
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    // e. Encrypt the data.
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    // f. Get the authentication tag. This is the "integrity check" part.
    const authTag = cipher.getAuthTag();

    // g. Combine all parts into a single string for easy storage/transmission.
    return `${salt.toString('hex')}:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

/**
 * Decrypts a payload created by the encrypt function.
 * @param {string} combinedPayload - The salt:iv:authTag:encryptedData string.
 * @returns {string} - The original plaintext.
 */
function decrypt(combinedPayload) {
    // a. Split the combined payload into its parts.
    const parts = combinedPayload.split(':');
    if (parts.length !== 4) {
        throw new Error('Invalid payload format. Expected 4 parts separated by colons.');
    }
    const [saltHex, ivHex, authTagHex, encryptedHex] = parts;

    // b. Convert all hex parts back into buffers.
    const salt = Buffer.from(saltHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const encrypted = Buffer.from(encryptedHex, 'hex');

    // c. Re-derive the *exact same key* using the master passphrase and the retrieved salt.
    const key = crypto.pbkdf2Sync(MASTER_PASSPHRASE, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512');

    // d. Create the decipher and provide the authentication tag.
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    // e. Decrypt the data. If the authTag is invalid (i.e., data was tampered with),
    // this `final()` call will throw an error.
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

// --- Express Web Server (No changes needed here) ---
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/encrypt', (req, res) => {
    const { text } = req.body;
    const encryptedPayload = encrypt(text);
    res.send(`
        <h1>Encrypted Payload:</h1>
        <p>This string contains the salt, IV, authentication tag, and encrypted data.</p>
        <textarea rows="10" cols="80" readonly>${encryptedPayload}</textarea>
        <br><br>
        <a href="/">Go Back</a>
    `);
});

app.post('/decrypt', (req, res) => {
    const { text } = req.body;
    try {
        const decryptedText = decrypt(text);
        res.send(`
            <h1>Decrypted Text:</h1>
            <p>${decryptedText}</p>
            <a href="/">Go Back</a>
        `);
    } catch (error) {
        console.error('Decryption failed:', error);
        res.status(400).send(`
            <h1>Error Decrypting Text</h1>
            <p>The payload was invalid or has been tampered with. Decryption failed.</p>
            <a href="/">Go Back</a>
        `);
    }
});

app.listen(port, () => {
  console.log(`Simple & Secure server listening at http://localhost:${port}`);
});
