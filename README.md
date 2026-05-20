# phishing-link-detectorr
The Phishing Link Detector is a cybersecurity web application developed using Python, Flask, and machine learning to identify malicious URLs. The system analyzes URL features and classifies links as safe or phishing, helping users avoid cyber threats, data theft, and online fraud.
# 🛡️ PhishGuard — Phishing URL Detection Tool

PhishGuard is a modern phishing URL detection web application built using Flask, HTML, CSS, and JavaScript.

It analyzes URLs for phishing indicators such as:
- Suspicious keywords
- Brand impersonation
- Unsafe TLDs
- URL shorteners
- IP-based URLs
- Excessive subdomains
- Known phishing domains
- HTTP usage without HTTPS

The application provides a risk score, risk level, and detailed detection signals for every scanned URL.

---

# 🚀 Features

## ✅ Single URL Scan
Analyze one URL instantly with a detailed phishing report.

## ✅ Batch URL Scan
Scan multiple URLs at once.

## ✅ Risk Scoring System
Every URL receives:
- Risk Score (0–100)
- Risk Level
- Phishing Status

## ✅ Detection Signals
Identifies:
- Brand spoofing
- Suspicious domains
- Dangerous redirects
- Numeric domains
- URL shorteners
- High-risk TLDs
- Raw IP addresses

## ✅ Modern UI
Cybersecurity-inspired responsive interface with:
- Animated score rings
- Dark futuristic theme
- Real-time analysis

## ✅ Flask Backend
REST API endpoints for:
- Single URL analysis
- Batch scanning

---

# 🧠 Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend logic |
| Flask | Web framework |
| HTML5 | Frontend structure |
| CSS3 | Styling & animations |
| JavaScript | Client-side detection |
| JSON | API communication |

---

# 📂 Project Structure

```plaintext
PhishGuard/
│
├── app.py
├── requirements.txt
├── README.md
│
├── static/
│   └── index.html
