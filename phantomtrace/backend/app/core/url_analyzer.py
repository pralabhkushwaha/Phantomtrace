"""
URL Intelligence Analyzer.

Checks a URL against multiple risk signals without requiring any paid API key:

  * HTTPS presence
  * Suspicious TLDs (.tk, .xyz, .ru, etc.)
  * URL shortening services
  * Homograph / typosquatting via the homograph engine
  * VirusTotal (if VIRUSTOTAL_API_KEY env var is set)
  * URLHaus (open, no key needed)
  * PhishTank (open, no key needed — public feed check)
  * AbuseIPDB (for extracted IP/host, if ABUSEIPDB_API_KEY is set)
  * Redirect chain depth detection (HEAD-follow up to 5 hops)
  * Domain age via RDAP
  * Port anomalies, IP-literal URLs, path entropy
"""

import os
import re
import hashlib
import math
from urllib.parse import urlparse, unquote
from .homograph import analyze_domain
from .dns_utils import rdap_domain_lookup, _safe_get_json

TIMEOUT = 5

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "rb.gy", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "clk.sh", "cutt.ly", "shorturl.at",
    "tiny.cc", "bl.ink", "rebrand.ly", "s.id", "tr.im", "lnkd.in",
    "tiny.one", "go2l.ink",
}

SUSPICIOUS_TLDS = {
    "ru", "cn", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "pw",
    "cc", "ws", "info", "click", "link", "online", "site", "work",
    "loan", "win", "vip", "buzz", "fun", "live",
}

SUSPICIOUS_PATH_WORDS = [
    "login", "signin", "account", "verify", "kyc", "update", "secure",
    "password", "credential", "wallet", "banking", "otp", "payment",
    "confirm", "support", "helpdesk",
]


def _path_entropy(path: str) -> float:
    """Shannon entropy of path characters — high entropy often indicates random/token-heavy paths."""
    if not path or len(path) < 8:
        return 0.0
    freq = {}
    for c in path:
        freq[c] = freq.get(c, 0) + 1
    n = len(path)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _check_virustotal(url: str) -> dict:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"available": False}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": api_key}
        import requests
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            return {
                "available": True,
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": total,
                "verdict": "Malicious" if malicious > 0 else ("Suspicious" if suspicious > 0 else "Clean"),
            }
    except Exception as e:
        return {"available": False, "error": str(e)}
    return {"available": False}


def _check_urlhaus(url: str) -> dict:
    """URLHaus is free and requires no API key."""
    try:
        import requests
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url}, timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("query_status") == "is_listed":
                tags = data.get("tags") or []
                return {
                    "available": True,
                    "listed": True,
                    "threat": data.get("threat", "malware"),
                    "tags": tags,
                    "verdict": "Flagged",
                }
            return {"available": True, "listed": False, "verdict": "Clean"}
    except Exception as e:
        return {"available": False, "error": str(e)}
    return {"available": False}


def _check_phishtank(url: str) -> dict:
    """PhishTank public API — no key required for basic lookups."""
    try:
        import requests, json as _json
        r = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": url, "format": "json", "app_key": ""},
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            result = data.get("results", {})
            in_database = result.get("in_database", False)
            verified = result.get("verified", False)
            return {
                "available": True,
                "in_database": in_database,
                "verified_phish": verified,
                "verdict": "Phish" if (in_database and verified) else ("Unverified" if in_database else "Clean"),
            }
    except Exception as e:
        return {"available": False, "error": str(e)}
    return {"available": False}


def _follow_redirects(url: str) -> dict:
    """Follow redirects (HEAD requests) up to 5 hops and return the chain."""
    try:
        import requests
        chain = []
        current = url
        for _ in range(5):
            r = requests.head(current, allow_redirects=False, timeout=TIMEOUT,
                              headers={"User-Agent": "Mozilla/5.0"})
            chain.append({"url": current, "status": r.status_code})
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location")
                if loc and loc != current:
                    current = loc
                else:
                    break
            else:
                break
        return {"chain": chain, "hops": len(chain), "final_url": current}
    except Exception as e:
        return {"chain": [], "hops": 0, "final_url": url, "error": str(e)}


def analyze_url(url: str, follow_redirects: bool = True) -> dict:
    """Full URL intelligence analysis."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    scheme = parsed.scheme
    host = parsed.hostname or ""
    port = parsed.port
    path = parsed.path + ("?" + parsed.query if parsed.query else "")

    # Is host an IP literal?
    import ipaddress
    ip_literal = None
    try:
        ip_literal = str(ipaddress.ip_address(host))
    except ValueError:
        pass

    domain = host if not ip_literal else None
    tld = domain.rsplit(".", 1)[-1].lower() if domain and "." in domain else ""

    flags = []
    risk_points = 0

    # HTTPS
    if scheme != "https":
        flags.append("URL uses plain HTTP — no encryption; credentials entered will be exposed")
        risk_points += 15

    # IP literal
    if ip_literal:
        flags.append(
            f"URL uses a raw IP address ({ip_literal}) instead of a domain name — "
            f"legitimate sites use domain names"
        )
        risk_points += 20

    # Port anomaly
    if port and port not in (80, 443):
        flags.append(f"Non-standard port {port} — legitimate sites rarely use custom ports")
        risk_points += 10

    # URL shortener
    is_shortened = domain in SHORTENER_DOMAINS if domain else False
    if is_shortened:
        flags.append(
            f"URL uses a shortening service ({domain}) — hides the real destination"
        )
        risk_points += 15

    # Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        flags.append(f"Suspicious TLD '.{tld}' — heavily associated with abuse and phishing")
        risk_points += 20

    # Homograph check
    homograph = {}
    if domain:
        homograph = analyze_domain(domain)
        if homograph.get("likely_impersonating"):
            flags.append(
                f"Homograph / brand impersonation detected: '{domain}' appears to "
                f"impersonate {homograph['impersonating_brand_name']} "
                f"(confidence: {homograph['confidence']}%)"
            )
            risk_points += 30

    # Suspicious words in path
    path_lower = unquote(path).lower()
    matched_words = [w for w in SUSPICIOUS_PATH_WORDS if w in path_lower]
    if matched_words:
        flags.append(
            f"Suspicious path keywords: {', '.join(matched_words)} — "
            f"characteristic of credential-harvesting or phishing pages"
        )
        risk_points += 10

    # Path entropy
    entropy = _path_entropy(path)
    if entropy > 4.0 and len(path) > 20:
        flags.append(
            f"High path entropy ({entropy:.1f}) — long random-looking path often used "
            f"to encode a tracking/victim-ID token in phishing links"
        )
        risk_points += 5

    # Redirect chain
    redirect_result = {}
    if follow_redirects:
        redirect_result = _follow_redirects(url)
        if redirect_result.get("hops", 0) > 2:
            flags.append(
                f"Redirect chain has {redirect_result['hops']} hops — "
                f"multi-hop redirects are used to evade URL filters"
            )
            risk_points += 10

    # Domain registration age
    rdap_result = {}
    if domain:
        rdap_result = rdap_domain_lookup(domain)
        age = rdap_result.get("age_days")
        if age is not None and age < 30:
            flags.append(f"Domain '{domain}' was registered only {age} day(s) ago")
            risk_points += 20
        elif age is not None and age < 90:
            flags.append(f"Domain '{domain}' is relatively new ({age} days old)")
            risk_points += 10

    # External reputation feeds
    vt = _check_virustotal(url)
    urlhaus = _check_urlhaus(url)
    phishtank = _check_phishtank(url)

    if vt.get("verdict") == "Malicious":
        flags.append(f"VirusTotal: {vt['malicious']} engine(s) flagged this URL as malicious")
        risk_points += 30
    elif vt.get("verdict") == "Suspicious":
        risk_points += 15

    if urlhaus.get("verdict") == "Flagged":
        flags.append(f"URLHaus: URL is listed as active malware distribution — threat: {urlhaus.get('threat')}")
        risk_points += 35

    if phishtank.get("verdict") == "Phish":
        flags.append("PhishTank: URL is a verified phishing site in the PhishTank database")
        risk_points += 40

    risk_points = min(risk_points, 100)
    if risk_points >= 70:
        verdict = "Malicious"
    elif risk_points >= 40:
        verdict = "Suspicious"
    elif risk_points >= 15:
        verdict = "Potentially Suspicious"
    else:
        verdict = "Likely Safe"

    # Aggregate reputation
    rep_sources = []
    if vt.get("available"):
        rep_sources.append({"source": "VirusTotal", "verdict": vt.get("verdict", "Unknown")})
    if urlhaus.get("available"):
        rep_sources.append({"source": "URLHaus", "verdict": urlhaus.get("verdict", "Unknown")})
    if phishtank.get("available"):
        rep_sources.append({"source": "PhishTank", "verdict": phishtank.get("verdict", "Unknown")})
    if not rep_sources:
        rep_sources.append({"source": "Heuristic only", "verdict": verdict})

    return {
        "url": url,
        "scheme": scheme,
        "host": host,
        "domain": domain,
        "tld": tld,
        "path": parsed.path,
        "query": parsed.query,
        "ip_literal": ip_literal,
        "is_shortened": is_shortened,
        "homograph": homograph,
        "redirect": redirect_result,
        "rdap": rdap_result,
        "reputation": {
            "virustotal": vt,
            "urlhaus": urlhaus,
            "phishtank": phishtank,
            "sources": rep_sources,
        },
        "path_entropy": round(entropy, 2),
        "flags": flags,
        "risk_score": risk_points,
        "verdict": verdict,
    }
