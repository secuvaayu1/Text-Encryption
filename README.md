# Text-Encryption

# AetherCrypt

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Made with Node.js](https://img.shields.io/badge/Node.js-18.x-339933?logo=node.js)](https://nodejs.org/)
[![Backend Deployed on Railway](https://img.shields.io/badge/Deployment-Railway-black?logo=railway)](https://railway.app)

AetherCrypt is a modern, secure web application for text encryption and decryption, featuring a stunning, interactive 3D animated interface. It demonstrates best practices in modern cryptography within a self-contained, easy-to-run project.

**[Link to your Live Demo Website on GitHub Pages Here]**

![AetherCrypt Screenshot](demo.png)
<!-- For this to work, add a screenshot of your app to the project folder and name it "demo.png" -->

## ✨ Features

-   **Strong, Authenticated Encryption:** Uses `AES-256-GCM` to provide both confidentiality and data integrity, preventing tampering.
-   **Robust Key Derivation:** Implements `PBKDF2` with a high iteration count to stretch a user-provided master passphrase into a strong encryption key, protecting against brute-force attacks.
-   **Secure Salting:** Generates a unique cryptographic salt for every encryption, ensuring identical inputs produce different encrypted outputs.
-   **Stunning 3D Interface:** Built with **Three.js**, the UI features an interactive particle field that reacts to mouse movement for an engaging user experience.
-   **Seamless UX:** The frontend communicates with the backend asynchronously, meaning the 3D animation is never interrupted while performing cryptographic operations.
-   **Self-Contained & Easy to Run:** The entire application runs with Node.js and has no external dependencies like databases or cloud services.

## 🛠️ Tech Stack

-   **Backend:** Node.js, Express.js, Node Crypto Module
-   **Frontend:** HTML5, CSS3, JavaScript (ES6+), Three.js
-   **Deployment:** GitHub Pages (Frontend), Railway (Backend)

## 🚀 Running Locally

Follow these instructions to get the project running on your local machine.

### Prerequisites

You need to have [Node.js](https://nodejs.org/) (version 14 or higher) and `npm` installed.


## 🔒 Security Concepts Implemented

-   **AES-256-GCM:** Galois/Counter Mode is an authenticated encryption mode. It bundles an "authentication tag" with the encrypted data. If a single bit of the ciphertext is altered, the tag becomes invalid, and decryption will fail, guaranteeing data integrity.

-   **PBKDF2 (Password-Based Key Derivation Function 2):** We don't use the master passphrase directly as the key. PBKDF2 takes the passphrase and a unique salt and puts it through a computationally intensive process (100,000 iterations). This makes it extremely slow for an attacker to guess passwords.

## 📄 License

This project is licensed under the MIT License.
