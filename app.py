from flask import Flask, request, jsonify, send_from_directory
import re
import urllib.parse
import os

app = Flask(__name__)

BLACKLISTED_DOMAINS = {
    "phishing-site.com", "malware-download.net", "fake-paypal.com",
    "secure-login-verify.com", "account-update-required.com",
    "banking-secure.net", "paypa1.com", "g00gle.com", "arnazon.com",
    "faceb00k.com", "micros0ft.com", "apple-id-verify.com",
    "netflix-billing-update.com", "irs-tax-refund.com",
    "verify-account-now.com", "free-gift-claim.net",
}

TRUSTED_DOMAINS = {
    "google.com", "google.co.in", "google.co.uk", "google.de",
    "google.fr", "google.com.au",
    "youtube.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de",
    "amazon.fr", "amazon.co.jp", "amazon.com.au",
    "microsoft.com", "live.com", "outlook.com", "office.com",
    "apple.com", "github.com", "wikipedia.org",
    "twitter.com", "x.com", "linkedin.com", "reddit.com",
    "netflix.com", "paypal.com", "stackoverflow.com", "medium.com",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "password", "credential", "confirm", "suspended",
    "unlock", "wallet", "paypal", "ebay", "bitcoin",
    "crypto", "urgent", "alert", "limited", "expires", "free-gift",
    "claim", "reward", "prize", "winner",
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
              "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}

SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
                   ".pw", ".top", ".click", ".link", ".zip", ".monster"}

BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "google.co.in", "google.co.uk", "google.de",
               "google.fr", "google.com.au"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de",
               "amazon.fr", "amazon.co.jp", "amazon.com.au"},
    "apple": {"apple.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com"},
    "facebook": {"facebook.com"},
    "netflix": {"netflix.com"},
    "ebay": {"ebay.com"},
    "instagram": {"instagram.com"},
}


def extract_domain(url: str):
    try:
        if "://" not in url:
            url = "http://" + url
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]
        return domain, parsed
    except Exception:
        return None, None


def is_ip_url(host: str) -> bool:
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host.split(":")[0]))


def analyze_url(url: str) -> dict:
    result = {
        "url": url,
        "risk_score": 0,
        "risk_level": "Safe",
        "flags": [],
        "is_phishing": False,
    }

    if not url or len(url.strip()) < 4:
        result.update({"flags": [("danger", "Empty or invalid URL")],
                       "risk_score": 100,
                       "risk_level": "Dangerous", "is_phishing": True})
        return result

    domain, parsed = extract_domain(url)
    if not domain:
        result["flags"].append(("warn", "Could not parse URL structure"))
        result["risk_score"] = 50
        result["risk_level"] = "Suspicious"
        return result

    url_lower = url.lower()
    score = 0
    flags = []

    parts = domain.split(".")
    root = ".".join(parts[-2:])
    is_trusted = (domain in TRUSTED_DOMAINS or root in TRUSTED_DOMAINS)

    # 1. Blacklist
    if domain in BLACKLISTED_DOMAINS:
        flags.append(("danger", "Domain is in known phishing blacklist"))
        score += 100

    # 2. Trusted whitelist
    if is_trusted:
        flags.append(("good", "Domain is a verified trusted site"))
        score = max(0, score - 30)

    # 3. IP-based URL
    if is_ip_url(domain):
        flags.append(("danger", "Raw IP address used instead of domain name"))
        score += 40

    # 4. Suspicious TLD
    if not is_trusted:
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                flags.append(("danger", f"High-risk TLD detected: {tld}"))
                score += 25
                break

    # 5. Excessive subdomains
    dot_count = domain.count(".")
    if dot_count >= 3:
        flags.append(("warn", f"Excessive subdomains ({dot_count} levels deep)"))
        score += 20

    # 6. Long URL
    if len(url) > 200:
        flags.append(("warn", f"Unusually long URL ({len(url)} characters)"))
        score += 15

    # 7. Suspicious keywords
    if not is_trusted:
        found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
        if len(found) >= 3:
            flags.append(("danger", f"Multiple suspicious keywords: {', '.join(found[:4])}"))
            score += 30
        elif len(found) >= 2:
            flags.append(("warn", f"Suspicious keywords found: {', '.join(found[:3])}"))
            score += 20
        elif len(found) == 1:
            flags.append(("warn", f"Suspicious keyword: {found[0]}"))
            score += 10

    # 8. Hyphens in domain
    if domain.count("-") >= 3:
        flags.append(("warn", "Excessive hyphens in domain name"))
        score += 15

    # 9. @ symbol
    if "@" in url:
        flags.append(("danger", "@ symbol found — classic URL redirect trick"))
        score += 35

    # 10. Double-slash redirect
    if re.search(r"https?://[^/]+//+", url):
        flags.append(("danger", "Double-slash redirect pattern detected"))
        score += 20

    # 11. Brand impersonation
    if not is_trusted:
        for brand, legit_domains in BRANDS.items():
            if brand in domain and domain not in legit_domains and root not in legit_domains:
                flags.append(("danger", f'Brand "{brand}" impersonated in domain'))
                score += 30
                break

    # 12. HTTP only
    if url_lower.startswith("http://") and not url_lower.startswith("https://"):
        flags.append(("warn", "No HTTPS — connection is unencrypted"))
        score += 10

    # 13. URL shortener
    for s in SHORTENERS:
        if s in domain:
            flags.append(("warn", f"URL shortener ({s}) hides the true destination"))
            score += 20
            break

    # 14. Numeric domain
    if re.match(r"^\d+$", domain.split(".")[0]):
        flags.append(("warn", "Domain name is purely numeric"))
        score += 15

    # 15. No flags = clean
    if not flags:
        flags.append(("good", "No suspicious indicators detected"))

    score = min(score, 100)

    if score <= 15:
        level, phishing = "Safe", False
    elif score <= 40:
        level, phishing = "Low Risk", False
    elif score <= 60:
        level, phishing = "Suspicious", True
    elif score <= 80:
        level, phishing = "High Risk", True
    else:
        level, phishing = "Dangerous", True

    result.update({
        "risk_score": score,
        "risk_level": level,
        "flags": flags,
        "is_phishing": phishing,
        "domain": domain,
    })
    return result


@app.route("/")
def index():
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    return send_from_directory(static_dir, "index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    return jsonify(analyze_url(url))


@app.route("/batch", methods=["POST"])
def batch():
    data = request.get_json(silent=True) or {}
    urls = [u.strip() for u in (data.get("urls") or []) if u.strip()]
    return jsonify([analyze_url(u) for u in urls])


if __name__ == "__main__":
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    os.makedirs(static_dir, exist_ok=True)
    print("🛡  PhishGuard running → http://localhost:5000")
    app.run(debug=True, port=5000)
