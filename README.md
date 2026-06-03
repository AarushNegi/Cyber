# 🔐 ZeroKey Auth

> Enterprise-grade Passwordless Authentication Platform built with Flask, MongoDB, FIDO2, and WebAuthn.

![Python](https://img.shields.io/badge/Python-3.12+-blue)
![Flask](https://img.shields.io/badge/Flask-Web_Framework-green)
![MongoDB](https://img.shields.io/badge/MongoDB-Database-success)
![FIDO2](https://img.shields.io/badge/FIDO2-Passwordless_Authentication-orange)
![WebAuthn](https://img.shields.io/badge/WebAuthn-Standard-red)

---

## 📖 Overview

ZeroKey Auth is a passwordless authentication system designed to replace traditional passwords with secure cryptographic authentication methods.

The project implements the FIDO2/WebAuthn standard and provides a modern authentication platform capable of:

- Passkey authentication
- Windows Hello support
- Biometric authentication
- Google OAuth SSO
- JWT-based session management
- Audit logging
- Account lockout protection
- Risk-based authentication

The goal is to eliminate password-related attacks while improving user experience and reducing IT support costs.

---
## 🔒 Access Notice

Registration is currently closed as this is a controlled security research deployment.

This is intentional — ZeroKey uses a registration lock feature to prevent unauthorised account creation on the live instance.

To explore the project locally, clone the repo and set `REGISTRATION_OPEN=true` in your `.env` file.
## 🎯 Problem Statement

Traditional authentication systems suffer from:

- Weak passwords
- Password reuse
- Credential stuffing
- Phishing attacks
- Brute-force attacks
- Password database breaches

ZeroKey replaces passwords with public-key cryptography and passkeys, ensuring that no reusable secret is transmitted during authentication.

---

## ✨ Features

### Authentication

- ✅ Passwordless Login (FIDO2/WebAuthn)
- ✅ Passkey Registration
- ✅ Passkey Authentication
- ✅ Windows Hello Integration
- ✅ Google OAuth SSO
- ✅ JWT Authentication

### Security

- ✅ Audit Logging
- ✅ Account Lockout Protection
- ✅ Replay Attack Protection
- ✅ Risk Engine
- ✅ Rate Limiting
- ✅ Secure Cookies
- ✅ HttpOnly JWT Tokens

### User Management

- ✅ Signup & Signin
- ✅ Dashboard
- ✅ Passkey Management
- ✅ Rename Passkeys
- ✅ Delete Passkeys
- ✅ Multi-Passkey Support

---

## 🏗 Architecture

```text
Client Layer
│
├── Browser (WebAuthn)
├── Windows Hello
├── Mobile Passkeys
└── Hardware Security Keys
        │
        ▼
Auth Gateway
│
├── Rate Limiting
├── Request Validation
└── Security Controls
        │
        ▼
Core Authentication Engine
│
├── FIDO2 Server
├── WebAuthn Verification
├── Risk Engine
└── Audit Logging
        │
        ▼
Identity & Access Layer
│
├── JWT Tokens
├── Google OAuth
└── Role Management (Planned)
        │
        ▼
MongoDB Database
```

---

## 🛠 Tech Stack

| Component | Technology |
|------------|------------|
| Backend | Flask |
| Database | MongoDB Atlas |
| Authentication | FIDO2 / WebAuthn |
| OAuth | Google OAuth |
| Security | JWT |
| Frontend | HTML, CSS, JavaScript |
| Hosting | Render |
| Version Control | GitHub |

---

## 📂 Project Structure

```text
ZeroKey/
│
├── app.py
├── db.py
├── fido2_store.py
├── audit.py
├── risk.py
├── setup_db.py
├── requirements.txt
│
├── static/
│   ├── auth.js
│   └── style.css
│
└── templates/
    ├── signup.html
    ├── signin.html
    └── dashboard.html
```

---

## 🔄 Authentication Flow

### Registration

1. User creates an account.
2. Server generates a challenge.
3. Browser invokes WebAuthn.
4. Authenticator creates a key pair.
5. Public key is stored in MongoDB.
6. Private key never leaves the device.

### Login

1. User enters username.
2. Server generates a challenge.
3. Windows Hello / Passkey signs challenge.
4. Server verifies signature.
5. JWT token is issued.
6. User gains access.

---

## 🛡 Security Features

### Audit Logging

Every authentication event is logged:

- Login Success
- Login Failure
- Logout
- Passkey Registration
- Passkey Deletion
- Google Authentication Events

### Risk Engine

Risk scoring based on:

- New IP addresses
- Unusual login times
- Multiple failed login attempts
- Recently locked accounts

### Account Lockout

- Locks account after repeated failed attempts
- Automatic unlock timer
- Prevents brute-force attacks

---

## 📊 Current Project Status

### Phase 1 — Foundation
- ✅ Database Schema
- ✅ FIDO2 Registration
- ✅ FIDO2 Authentication
- ✅ Passkey Management

### Phase 2 — Integration
- ✅ Google OAuth
- ✅ Registration Controls
- ⏳ RBAC (In Progress)

### Phase 3 — Security Hardening
- ✅ Audit Logging
- ✅ Account Lockout
- ✅ Risk Engine
- ⏳ CSP Security Headers

### Phase 4 — Future Roadmap
- Multi-Tenant Architecture
- API Keys
- SDK for Developers
- Auth-as-a-Service Platform

---

## 🚀 Installation

### Clone Repository

```bash
git clone https://github.com/AarushNegi/Cyber.git
cd Cyber
```

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Environment

Windows:

```bash
venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Application

```bash
python app.py
```

Open:

```text
http://localhost:5000
```

---

## 📈 Future Enhancements

- Role-Based Access Control (RBAC)
- CSP with Nonce Support
- Hardware Security Key Testing
- Multi-Tenant Support
- SIEM Integration
- ISO 27001 Alignment
- SOC 2 Readiness
- Auth SDK

---

## 👨‍💻 Author

**Aarush H. Negi**

Cybersecurity Student | Security Researcher | Developer

GitHub:
https://github.com/AarushNegi

---

## ⭐ Why ZeroKey?

ZeroKey demonstrates how modern authentication systems can eliminate password-related risks through FIDO2 and WebAuthn while providing a seamless user experience.

This project serves as both a practical cybersecurity implementation and a foundation for a future enterprise authentication platform.
