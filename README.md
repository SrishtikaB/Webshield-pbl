# 🛡️ WebShield – Rule-Based URL Phishing Detection System

### 1. Project Description
WebShield is a rule-based phishing detection system that analyzes URLs using predefined cybersecurity rules. It evaluates suspicious characteristics, assigns a risk score, and classifies URLs as **Safe**, **Suspicious**, or **Fake (Phishing)**.

### 2. Problem Statement
Phishing attacks exploit deceptive URLs to steal sensitive information. Identifying malicious links is difficult for everyday users. WebShield provides a lightweight and explainable solution by detecting phishing indicators directly from a URL before the user visits the website.

### 3. Detection Rules
WebShield analyzes URLs based on multiple security indicators, including:

- IP Address in URL
- Presence of **@** symbol
- Punycode (Homograph attacks)
- Suspicious keywords (login, verify, secure, password, etc.)
- Brand impersonation
- Suspicious domain extensions
- Long domain names
- Multiple subdomains
- Hyphen abuse
- Missing HTTPS

### 4. Workflow

1. User enters a URL.
2. System extracts URL features.
3. Security rules are evaluated.
4. Risk score is calculated.
5. URL is classified as:
   - **0–29** → ✅ Safe
   - **30–59** → ⚠️ Suspicious
   - **60+** → 🚨 Fake (Phishing)

### 5. Technologies Used

**Frontend**
- HTML5
- CSS3
- JavaScript

**Backend**
- Python
- Flask
- Flask-CORS

**Deployment**
- Render

### 6. Live Demo

🔗 **https://webshield-pbl.onrender.com**

Simply enter a URL and click **Analyze URL** to receive its security assessment.

### 7. Future Enhancements

- WHOIS Domain Lookup
- SSL Certificate Verification
- Browser Extension
- QR Code URL Scanning
- Threat Intelligence Integration
- Machine Learning-based Detection
