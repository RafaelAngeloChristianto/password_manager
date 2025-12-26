🔐 Secure Password Manager (Python + Tkinter)

A local, encrypted password manager built with Python and Tkinter.
All credentials are securely encrypted using a master password and never stored in plaintext.

This project demonstrates practical knowledge of cryptography, secure key derivation, and GUI development.

✨ Features

🔑 Master Password Authentication

🔒 Strong Encryption

PBKDF2-HMAC (SHA-256)

300,000 iterations

Fernet (AES-128 + HMAC)

🧂 Secure random salt generation

🖥️ User-friendly Tkinter GUI

🔄 Load, save, and delete credentials

👁️ Toggle password visibility

🎲 Cryptographically secure password generator

💾 Encrypted vault stored locally (vault.sec)

🛡️ Security Design
Component	Description
Key Derivation	PBKDF2-HMAC with SHA-256
Iterations	300,000
Salt	Random 16-byte salt (salt.bin)
Encryption	Fernet (AES + HMAC)
Storage	Fully encrypted JSON vault

Even if vault.sec is stolen, it cannot be decrypted without the master password.

📂 Project Structure
.
├── main.py          # Password Manager application
├── vault.sec        # Encrypted password vault (auto-created)
├── salt.bin         # Cryptographic salt (auto-created)
└── README.md

🚀 Installation
1. Clone the repository
git clone https://github.com/yourusername/secure-password-manager.git
cd secure-password-manager

2. Install dependencies
pip install cryptography


Tkinter is included with most Python installations.

▶️ Usage

Run the application:

python main.py

First Run

You will be prompted to create a master password

A new encrypted vault will be created automatically

Next Runs

Enter the same master password to unlock your vault

Wrong password → vault remains inaccessible

🔑 Password Generator

Choose length between 8–64 characters

Uses:

Uppercase & lowercase letters

Numbers

Symbols

Generated with Python’s secrets module (cryptographically secure)

⚠️ Important Notes

❗ If you forget your master password, your data cannot be recovered

❗ Deleting salt.bin will permanently break vault decryption

This app is offline-only by design for maximum security

🎯 Why This Project Matters (Portfolio)

This project demonstrates:

Practical cryptography (not just theory)

Secure key handling & password-based encryption

Defensive security mindset

GUI application development

Secure local data storage

Perfect for:

Cybersecurity portfolios

Blue team / defensive security roles

Python security projects

University or CTF-related showcases

🧠 Future Improvements

Clipboard auto-clear

Search & filter entries

Auto-lock timer

Vault export/import

Two-factor authentication (2FA)

📜 License

This project is for educational purposes.
Use responsibly.