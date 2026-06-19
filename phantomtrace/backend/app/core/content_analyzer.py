"""
Email body / subject content analyzer.

Pure rule-based (regex + keyword) classifier covering the social-engineering
patterns most common in phishing emails targeting Indian + global users,
including Hindi/Hinglish phrasing frequently seen in SMS/email/WhatsApp scams.

This is deliberately NOT a black-box ML model: every flag is explainable
(which phrase triggered it), which matters for an evidence report a police
officer or analyst will have to justify.
"""

import re

# Each category: list of (regex_pattern, weight). Patterns are case-insensitive.
CATEGORY_PATTERNS = {
    "urgency": [
        (r"\burgent(ly)?\b", 8), (r"\bimmediately\b", 8), (r"\bact now\b", 10),
        (r"\bwithin\s+(\d+\s*)?(hours?|24\s*hrs?|hrs)\b", 9),
        (r"\bexpir(es?|ing|ed)\b", 7), (r"\blast\s+(chance|warning)\b", 9),
        (r"\bsuspend(ed|ing)?\b", 8), (r"\bdeactivat(e|ed|ion)\b", 8),
        (r"\bfinal\s+notice\b", 9), (r"\btoday\s+only\b", 7),
        (r"\bturant\b", 8), (r"\bjaldi\b", 7), (r"\babhi\b", 5),  # Hinglish
    ],
    "fear": [
        (r"\bsuspicious activity\b", 9), (r"\baccount\s+(has\s+been\s+)?compromis", 10),
        (r"\bunauthoriz(ed|ation)\b", 8), (r"\blegal action\b", 9), (r"\bfir\b", 8),
        (r"\bpolice\s+complaint\b", 8), (r"\bblock(ed)?\s+(permanently|account)\b", 8),
        (r"\bpenalty\b", 6), (r"\barrest\b", 9), (r"\bfraud(ulent)? (detected|alert)\b", 8),
    ],
    "reward": [
        (r"\byou\s+(have\s+)?won\b", 10), (r"\blottery\b", 10), (r"\bcongratulations\b", 6),
        (r"\bcashback\b", 6), (r"\bfree\s+gift\b", 8), (r"\bclaim\s+your\s+prize\b", 10),
        (r"\blucky\s+(draw|winner)\b", 9), (r"\breward\s+points\b", 5), (r"\bbumper\s+prize\b", 9),
    ],
    "credential_theft": [
        (r"\bverify\s+your\s+(password|account|identity|details)\b", 10),
        (r"\bclick\s+here\s+to\s+(login|log in|verify|sign in)\b", 10),
        (r"\bupdate\s+your\s+(details|information|kyc|profile)\b", 9),
        (r"\bconfirm\s+your\s+(password|account|email)\b", 9),
        (r"\bre-?enter\s+your\s+(password|credentials)\b", 9),
        (r"\bsign\s*in\s+to\s+(continue|verify)\b", 7),
    ],
    "otp_request": [
        (r"\botp\b", 9), (r"\bone[\s-]time\s+password\b", 9),
        (r"\bshare\s+(the\s+|your\s+)?(otp|code|pin)\b", 10),
        (r"\bverification\s+code\b", 7), (r"\bsend\s+(us\s+)?the\s+code\b", 8),
    ],
    "banking_scam": [
        (r"\bkyc\b", 8), (r"\baccount\s+(has\s+been\s+)?(blocked|frozen|suspended)\b", 9),
        (r"\bre-?kyc\b", 9), (r"\bdebit\s+card\s+block", 8), (r"\bpan\s+card\b", 6),
        (r"\baadhaar\b", 6), (r"\bupdate\s+your\s+bank\b", 9), (r"\bnet\s*banking\b", 5),
        (r"\bibd\s+(deactivat|block)", 8), (r"\bupi\s+(id|pin)\s+(block|expir|verify)", 8),
    ],
    "apk_scam": [
        (r"\.apk\b", 10), (r"\bdownload\s+(the\s+)?app(lication)?\b", 7),
        (r"\binstall\s+(the\s+)?app(lication)?\b", 8), (r"\bandroid\s+app\b", 5),
        (r"\bapk\s+file\b", 10), (r"\bopen\s+with\s+package\s+installer\b", 9),
        (r"\bapk\b", 9),
    ],
}

CATEGORY_LABELS = {
    "urgency": "Urgency Pressure Tactics",
    "fear": "Fear / Threat Language",
    "reward": "Fake Reward / Lottery Lure",
    "credential_theft": "Credential Theft Attempt",
    "otp_request": "OTP / Verification Code Request",
    "banking_scam": "Banking / KYC Scam Language",
    "apk_scam": "APK Download Scam",
}


def analyze_content(text: str, subject: str = "") -> dict:
    """
    Returns:
      {
        categories: { name: {matched: bool, score: int, matches: [phrase,...]} },
        overall_risk_score: 0-100,
        risk_level: Low/Medium/High/Critical,
        detected_labels: ["APK Download Scam Detected", ...]
      }
    """
    full_text = f"{subject}\n{text or ''}"
    categories = {}
    total_score = 0
    detected_labels = []

    for cat, patterns in CATEGORY_PATTERNS.items():
        matches = []
        cat_score = 0
        for pattern, weight in patterns:
            found = re.findall(pattern, full_text, flags=re.IGNORECASE)
            if found:
                cat_score += weight
                # re-find the actual matched substring for the evidence trail
                m = re.search(pattern, full_text, flags=re.IGNORECASE)
                if m:
                    matches.append(m.group(0))

        cat_score = min(cat_score, 40)  # cap a single category's contribution
        categories[cat] = {
            "label": CATEGORY_LABELS[cat],
            "matched": cat_score > 0,
            "score": cat_score,
            "matches": matches,
        }
        if cat_score > 0:
            total_score += cat_score
            risk_word = "High" if cat_score >= 18 else "Medium"
            detected_labels.append(f"{CATEGORY_LABELS[cat]} Detected — Risk: {risk_word}")

    overall = min(total_score, 100)
    if overall >= 60:
        level = "Critical"
    elif overall >= 35:
        level = "High"
    elif overall >= 15:
        level = "Medium"
    else:
        level = "Low"

    return {
        "categories": categories,
        "overall_risk_score": overall,
        "risk_level": level,
        "detected_labels": detected_labels,
    }
