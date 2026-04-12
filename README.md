# WebShield – Rule-Based URL Link Checker

1. Project Description:
WebShield is a rule-based phishing detection system that analyzes URLs using predefined security rules. It assigns a score based on suspicious features and classifies links as Safe, Suspicious, or Phishing.


2.Problem Statement:
Many users fall victim to phishing and malicious links. It is difficult for common users to identify unsafe URLs. This project aims to check the safety of a URL using predefined rules.

3.Detection Rules:
IP address in URL
Presence of @ symbol
Suspicious keywords (login, verify, secure, etc.)
Brand impersonation patterns
Suspicious domain extensions
Long or complex domain names
Multiple subdomains
Hyphen abuse
Punycode (homograph attacks)

 How It Works:
1. User enters a URL  
2. System extracts features (length, symbols, keywords, etc.)  
3. Each feature is assigned a score  
4. Total score determines classification:  
   0–29 → Safe
   30–59 → Suspicious  
   60+ → Phishing

Technologies Used:
Frontend: HTML, CSS, JavaScript  
Backend: Python (Flask)  
Deployment: Render, GitHub Pages  

 Live Demo:
 first open this link in browser: https://webshield-pbl.onrender.com 
 and then open this link: https://srishtikab.github.io/Webshield-pbl/

 Webpage link: https://visionary-praline-f6d71c.netlify.app




