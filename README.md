# 🛡️ WebShield

**Rule-based phishing URL detection with a real-time risk analysis dashboard.**

WebShield inspects a URL against 30+ weighted security rules and returns a risk score, threat level, and confidence rating in seconds.

🔗 **Live demo:** [webshield-pbl.onrender.com](https://webshield-pbl.onrender.com)

---

## How it works

1. User submits a URL.
2. Flask backend parses it and runs 30 detection rules across three categories — **Structure**, **Content**, and **Domain Intel** — plus 5 trust signals (HTTPS, `.gov`/`.edu`/`.org`, clean domain structure).
3. Weighted points produce a **risk score (0–100)** and a **confidence rating**, based on how much evidence was found.
4. URL is classified:

   | Score | Verdict |
   |---|---|
   | 0–29 | ✅ Safe |
   | 30–59 | ⚠️ Suspicious |
   | 60+ | 🚨 Fake / Phishing |

## What it checks

IP-based URLs, missing HTTPS, `@` obfuscation, punycode/homograph attacks, suspicious keywords (`login`, `verify`, `secure`...), brand impersonation, URL shorteners, suspicious TLDs, excessive subdomains/hyphens/query params, encoded characters, entropy-based domain randomness, and more — offset by trust signals like trusted TLDs and clean domain structure.

## Tech stack

| | |
|---|---|
| **Frontend** | HTML5, CSS3, JavaScript |
| **Backend** | Python, Flask, Flask-CORS |
| **Deployment** | Render |

## Run locally

```bash
git clone https://github.com/<your-username>/Webshield-pbl.git
cd Webshield-pbl
pip install -r requirements.txt
python app.py
```

Visit `http://localhost:5000`.

## Roadmap

- WHOIS domain lookup
- SSL certificate verification
- Browser extension
- ML-based detection

---

<sub>Built as a cybersecurity project demonstrating explainable, rule-based phishing detection.</sub>
