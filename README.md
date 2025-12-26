# 🔐 Secure Password Manager  
**Python • Tkinter • Cryptography**

A **local, offline, encrypted password manager** built with **Python and Tkinter**.  
All credentials are securely encrypted using a **master password** and are **never stored in plaintext**.

This project demonstrates **practical cryptography**, **secure key derivation**, and **GUI application development**.

---

## ✨ Features

- 🔑 **Master Password Authentication**
- 🔒 **Strong Encryption**
  - PBKDF2-HMAC (SHA-256)
  - 300,000 iterations
  - Fernet (AES-128 + HMAC)
- 🧂 Secure random salt generation
- 🖥️ User-friendly **Tkinter GUI**
- 🔄 Add, load, update, and delete credentials
- 👁️ Toggle password visibility
- 🎲 Cryptographically secure password generator
- 💾 Fully encrypted local vault (`vault.sec`)
- 🛡️ Offline-only by design

---

## 🛡️ Security Architecture

| Component        | Description                                  |
|------------------|----------------------------------------------|
| Key Derivation   | PBKDF2-HMAC (SHA-256)                         |
| Iterations       | 300,000                                      |
| Salt             | Random 16-byte salt (`salt.bin`)              |
| Encryption       | Fernet (AES-128 + HMAC)                       |
| Storage Format   | Fully encrypted JSON                          |

> **Even if `vault.sec` is stolen, it cannot be decrypted without the master password.**

---

## 📂 Project Structure
├── main.py # Password Manager application
├── vault.sec # Encrypted password vault (auto-created)
├── salt.bin # Cryptographic salt (auto-created)
└── README.md


---

## 🚀 Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/yourusername/secure-password-manager.git
cd secure-password-manager

2️⃣ Install dependencies

pip install cryptography

    Note: Tkinter is included with most Python installations.

▶️ Usage

Run the application:

python main.py

First Run

    You will be prompted to create a master password

    A new encrypted vault is created automatically

Subsequent Runs

    Enter the same master password to unlock your vault

    ❌ Incorrect password → vault remains inaccessible
```

🔑 Password Generator

    Adjustable length: 8–64 characters

    Uses Python’s secrets module (cryptographically secure)

    Character set includes:

        Uppercase & lowercase letters

        Numbers

        Symbols

⚠️ Important Security Notes

    ❗ If you forget your master password, your data cannot be recovered

    ❗ Deleting salt.bin permanently breaks vault decryption

    🔒 This application is offline-only by design for maximum security

🎯 Why This Project Matters (Portfolio)

This project demonstrates:

    ✔️ Real-world cryptography (not just theory)

    ✔️ Secure password-based key derivation

    ✔️ Defensive security mindset

    ✔️ GUI development with Tkinter

    ✔️ Secure local data storage

Ideal for:

    Cybersecurity portfolios

    Blue Team / Defensive Security roles

    Python security projects

    University assignments or CTF showcases

🧠 Future Improvements

    Clipboard auto-clear timer

    Search & filter credentials

    Auto-lock on inactivity

    Vault export/import

    Two-factor authentication (2FA)
