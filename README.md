# SessionGuard: A JWT-Based Session Hijacking Risk Assessment Tool

SessionGuard is an automated authentication security audit tool that analyzes JWT-based login and session management implementations. It answers the central security question:
> **"If an attacker stole or forged this session token, how completely and for how long could they hijack this user's account?"**

---

## 🎯 Project Architecture (50% Presentation Milestone)

The system is composed of two distinct components:

1. **Part A: Controlled Target Application (`app/`)**
   - Realistic Flask authentication portal with `/login`, `/dashboard`, `/logout`, and SQLite database.
   - Dual-mode architecture toggleable on the fly:
     - **Vulnerable Mode**: Weak signing key (`"secret"`), accepts `alg: none` unsigned tokens, 30-day token lifetime, and client `localStorage`.
     - **Hardened Mode**: 256-bit cryptographic secret, strict HS256 signature verification, 15-minute token lifetime, server-side revocation blacklist, and `HttpOnly; SameSite=Lax` cookies.

2. **Part B: SessionGuard Security Core & CLI (`sessionguard/`)**
   - **JWT Claim & Timestamp Decoder**: Parses header, claims, issued/expiration dates, and calculates active lifetime.
   - **High-Speed HMAC Dictionary Cracker**: Offline HMAC-SHA256 dictionary engine cracking weak keys in milliseconds.
   - **`alg: none` Signature Bypass Probe**: Crafts unsigned tokens and tests server-side signature enforcement.
   - **Token Expiration Evaluator**: Validates `exp` claim presence, expiry status, and checks for excessive session windows (OWASP ASVS V3.3).
   - **Risk Scoring Engine**: Computes Exploitability (1–3) $\times$ Impact (1–3) risk scores (1–9 scale) and maps findings to **CWE-347**, **CWE-798**, **CWE-613**, and **OWASP Top 10 A07:2021**.
   - **Terminal Reporter**: Colorized security matrix and executive risk assessment.

---

## 🚀 Quick Start Guide

### 1. Activate Environment
Ensure you are using the project virtual environment:
```powershell
.venv\Scripts\activate
```

### 2. Launch the Target Application (Part A)
```powershell
python run_target.py
```
Open **`http://127.0.0.1:5000`** in your browser.
- Default Admin Account: `admin` / `admin2026`
- Toggle between **Vulnerable** and **Hardened** modes using the dropdown in the top-right navigation bar.

### 3. Launch the SessionGuard Web GUI Console (Part B - Recommended for Presentations)
```powershell
python run_web_analyzer.py
```
Open **`http://127.0.0.1:5001`** in your browser.
- **Interactive Security Dashboard**: Paste any session token from the target app to execute an independent black-box security audit.
- **Visual Risk Gauge (1–9)**: Displays live Critical/High/Low scores, cracking stats, and executive verdicts.
- **Detailed Findings & Remediation**: View exact vulnerability details and code fixes.
- **Export Options**: 1-click JSON export and printable PDF reports.

---

## 🔍 How to Run SessionGuard CLI (Alternative Command Line)

### 1. Full Security Audit (Token + Live Server Verification)
```powershell
python run_sessionguard.py analyze "<JWT_TOKEN>" --target http://127.0.0.1:5000
```

### 2. Standalone Offline Secret Cracker
```powershell
python run_sessionguard.py crack "<JWT_TOKEN>"
```

### 3. Decode & Humanize Claims
```powershell
python run_sessionguard.py decode "<JWT_TOKEN>"
```

### 4. JSON Export (For CI/CD or automation)
```powershell
python run_sessionguard.py analyze "<JWT_TOKEN>" --json
```

---

## 🎤 Presentation Demo Walkthrough (For Your Teacher)

Follow these steps for a live demonstration:

1. **Step 1: Start the Target App**
   - Run `python run_target.py`.
   - Open `http://127.0.0.1:5000`. Show the clean login interface.
   - Sign in with `admin` / `admin2026`.
   - On the Dashboard, click the **"Copy Token"** button.

2. **Step 2: Demonstrate Vulnerable Mode Analysis**
   - Open terminal and run:
     ```powershell
     python run_sessionguard.py analyze "<COPIED_TOKEN>" --target http://127.0.0.1:5000
     ```
   - **Highlight to your teacher**:
     - `HMAC Secret Key Strength`: **[FAIL] CRITICAL (9/9)** – The dictionary engine cracked the secret (`'secret'`) in under 1 millisecond!
     - `Algorithm 'none' Bypass`: **[FAIL] CRITICAL (9/9)** – The tool dynamically forged an unsigned token and proved the server accepted it (CWE-347).
     - `Session Expiration`: **[FAIL] HIGH (6/9)** – Token is valid for 30 days without re-authentication (CWE-613).
     - **Overall Score**: **CRITICAL 9/9** – Complete account takeover possible.

3. **Step 3: Switch to Hardened Mode and Re-test**
   - In the web app header dropdown, switch the mode to **"Hardened (Secure)"**.
   - Log in again and copy the new token.
   - Run the same command:
     ```powershell
     python run_sessionguard.py analyze "<NEW_TOKEN>" --target http://127.0.0.1:5000
     ```
   - **Highlight to your teacher**:
     - All 3 checks **[PASS]** with **LOW (1/9)** score.
     - Signature bypass rejected.
     - 256-bit entropy resisted dictionary cracking.
     - Token validity restricted to 15 minutes (OWASP ASVS compliant).

4. **Step 4: Run Automated Unit Tests**
   - Run:
     ```powershell
     python -m unittest discover -s tests -v
     ```
   - Show all 12 tests passing.

---

## 📁 Repository Structure

```
d:/EHPT Project/
├── app/                        # Part A: Target Application
│   ├── app.py                  # Auth routes (/login, /dashboard, /logout)
│   ├── config.py               # Vulnerable vs Hardened security profiles
│   ├── db.py                   # SQLite database & token blacklist
│   ├── templates/              # HTML templates (base, login, dashboard)
│   └── static/                 # CSS & JavaScript
├── sessionguard/               # Part B: SessionGuard Security Core
│   ├── core/
│   │   ├── decoder.py          # Claim decoding & timestamp humanization
│   │   ├── cracker.py          # High-speed HMAC-SHA256 dictionary cracker
│   │   ├── risk_engine.py      # Exploitability x Impact scoring engine
│   │   └── checks/             # Modular check plugins
│   │       ├── base.py         # Abstract Check interface
│   │       ├── alg_none.py     # CWE-347 signature bypass check
│   │       ├── weak_secret.py  # CWE-798 weak HMAC key check
│   │       └── expiration.py   # CWE-613 token lifetime check
│   ├── reports/
│   │   └── console_reporter.py # Rich colorized terminal reporter
│   ├── wordlists/
│   │   └── jwt_secrets.txt     # 150+ common JWT secrets
│   ├── scanner.py              # Audit orchestrator
│   └── cli.py                  # CLI parser
├── tests/                      # Automated unit test suite
├── run_target.py               # Target app launcher (Port 5000)
├── run_sessionguard.py         # SessionGuard CLI launcher
└── requirements.txt            # Project dependencies
```
