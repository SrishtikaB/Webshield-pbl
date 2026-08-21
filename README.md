# 🛡️ WebShield

**A hybrid phishing URL detector — rule-based scoring engine + Google Safe Browsing, benchmarked on a 1,000-URL real-world dataset.**

🔗 **Live demo:** [webshield-pbl.onrender.com](https://webshield-pbl.onrender.com)

---

## Overview

WebShield analyzes a URL through **28 weighted detection rules** and a live **Google Safe Browsing** lookup, returning a risk score, verdict, and a transparent breakdown of exactly why a link was flagged — no black box.

| Score | Verdict |
|---|---|
| 0–14 | ✅ Safe |
| 15–39 | ⚠️ Suspicious |
| 40+ | 🚨 Fake / Phishing |

## Detection signals

`IP-based URLs` · `Missing HTTPS` · `@ obfuscation` · `Punycode/homograph attacks` · `Suspicious keywords` · `Brand impersonation` · `URL shorteners` · `Suspicious TLDs` · `Excessive subdomains/hyphens/params` · `Encoded characters` · `Domain entropy` — offset by trust signals (`.gov`/`.edu`, clean domain structure) and a live Google threat-database cross-check.

## Benchmarked accuracy

Tested on 1,000 real URLs — 500 verified phishing (PhishTank) + 500 real popular sites (Chrome UX Report) — not assumed, measured.

| Metric | Result |
|---|---|
| **Accuracy** | **74.6%** |
| Precision | 92.4% |
| Recall | 53.6% |
| F1 Score | 0.679 |
| False Positive Rate | 4.4% |

Full per-rule performance breakdown: [`WebShield_28_Rules_Report`](./WebShield_28_Rules_Report.docx)

## Stack

`Python` · `Flask` · `Flask-CORS` · `Google Safe Browsing API v4` · `HTML/CSS/JS` · `Render`

## Run locally

```bash
git clone https://github.com/<your-username>/Webshield-pbl.git
cd Webshield-pbl
pip install -r requirements.txt

# optional — app runs fine without it, just skips the Safe Browsing check
export GOOGLE_SAFE_BROWSING_API_KEY=your_key_here

python app.py
```

Visit `http://localhost:5000`.

## Roadmap

- [ ] WHOIS domain age lookup
- [ ] SSL certificate verification
- [ ] Browser extension
- [ ] ML model trained on the same dataset, benchmarked against this baseline

---

<sub>Built as a cybersecurity project demonstrating explainable, evidence-validated phishing detection.</sub>
