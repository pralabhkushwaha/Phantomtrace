"""
Email body / subject content analyzer.

Rule-based classifier covering social-engineering patterns most common in
phishing emails targeting Indian + global users, including India-specific
scam formats (Digital Arrest, UPI Fraud, OLX Scam, Loan App, SIM Swap,
Investment Scam) that are UP Police cyber cell priorities.
"""

import re

CATEGORY_PATTERNS = {
    "urgency": [
        (r"\burgent(ly)?\b", 8), (r"\bimmediately\b", 8), (r"\bact now\b", 10),
        (r"\bwithin\s+(\d+\s*)?(hours?|24\s*hrs?|hrs)\b", 9),
        (r"\bexpir(es?|ing|ed)\b", 7), (r"\blast\s+(chance|warning)\b", 9),
        (r"\bsuspend(ed|ing)?\b", 8), (r"\bdeactivat(e|ed|ion)\b", 8),
        (r"\bfinal\s+notice\b", 9), (r"\btoday\s+only\b", 7),
        (r"\bturant\b", 8), (r"\bjaldi\b", 7), (r"\babhi\b", 5),
        (r"\blast\s+date\b", 8), (r"\bdeadline\b", 7),
    ],
    "fear": [
        (r"\bsuspicious activity\b", 9), (r"\baccount\s+(has\s+been\s+)?compromis", 10),
        (r"\bunauthoriz(ed|ation)\b", 8), (r"\blegal action\b", 9), (r"\bfir\b", 8),
        (r"\bpolice\s+complaint\b", 8), (r"\bblock(ed)?\s+(permanently|account)\b", 8),
        (r"\bpenalty\b", 6), (r"\barrest\b", 9), (r"\bfraud(ulent)? (detected|alert)\b", 8),
        (r"\bcourt\s+(notice|order|summons)\b", 10), (r"\bcyber\s+crime\b", 8),
        (r"\bwarrant\b", 10), (r"\bjail\b", 9), (r"\bimprison\b", 9),
    ],
    "reward": [
        (r"\byou\s+(have\s+)?won\b", 10), (r"\blottery\b", 10), (r"\bcongratulations\b", 6),
        (r"\bcashback\b", 6), (r"\bfree\s+gift\b", 8), (r"\bclaim\s+your\s+prize\b", 10),
        (r"\blucky\s+(draw|winner)\b", 9), (r"\breward\s+points\b", 5), (r"\bbumper\s+prize\b", 9),
        (r"\bselected\s+as\s+a\s+(lucky|winner)\b", 9), (r"\brs\.?\s*\d+[\d,]+\b", 7),
        (r"\blakh(s)?\b", 6), (r"\bcrore(s)?\b", 7),
    ],
    "credential_theft": [
        (r"\bverify\s+your\s+(password|account|identity|details)\b", 10),
        (r"\bclick\s+here\s+to\s+(login|log in|verify|sign in)\b", 10),
        (r"\bupdate\s+your\s+(details|information|kyc|profile)\b", 9),
        (r"\bconfirm\s+your\s+(password|account|email)\b", 9),
        (r"\bre-?enter\s+your\s+(password|credentials)\b", 9),
        (r"\bsign\s*in\s+to\s+(continue|verify)\b", 7),
        (r"\benter\s+your\s+(pin|mpin|password)\b", 10),
    ],
    "otp_request": [
        (r"\botp\b", 9), (r"\bone[\s-]time\s+password\b", 9),
        (r"\bshare\s+(the\s+|your\s+)?(otp|code|pin)\b", 10),
        (r"\bverification\s+code\b", 7), (r"\bsend\s+(us\s+)?the\s+code\b", 8),
        (r"\bmpin\b", 9), (r"\btransaction\s+(pin|password)\b", 9),
    ],
    "banking_scam": [
        (r"\bkyc\b", 8), (r"\baccount\s+(has\s+been\s+)?(blocked|frozen|suspended)\b", 9),
        (r"\bre-?kyc\b", 9), (r"\bdebit\s+card\s+block", 8), (r"\bpan\s+card\b", 6),
        (r"\baadhaar\b", 6), (r"\bupdate\s+your\s+bank\b", 9), (r"\bnet\s*banking\b", 5),
        (r"\bupi\s+(id|pin)\s*(block|expir|verify|update)", 8),
        (r"\bkyc\s+(expir|updat|verif)\w+", 10),
        (r"\bsbi|hdfc|icici|axis\s+bank|kotak|pnb\b", 5),
    ],
    "apk_scam": [
        (r"\.apk\b", 10), (r"\bdownload\s+(the\s+)?app(lication)?\b", 7),
        (r"\binstall\s+(the\s+)?app(lication)?\b", 8), (r"\bandroid\s+app\b", 5),
        (r"\bapk\s+file\b", 10), (r"\bopen\s+with\s+package\s+installer\b", 9),
        (r"\bapk\b", 9), (r"\bwhatsapp.*apk|apk.*whatsapp\b", 12),
    ],
    "digital_arrest_scam": [
        (r"\bdigital\s+arrest\b", 20),
        (r"\bcbi\s+(officer|agent|notice)\b", 15),
        (r"\bed\s+(enforcement|directorate)\b", 12),
        (r"\bnarcotics\s+(bureau|officer|case)\b", 12),
        (r"\bmoney\s+launder(ing|ed)\b", 10),
        (r"\binterpol\b", 12),
        (r"\bcustoms\s+(officer|department|notice)\b", 10),
        (r"\bparcel\s+(seized|held|blocked|contain)\b", 12),
        (r"\bstay\s+on\s+(call|line|video)\b", 15),
        (r"\bdo\s+not\s+(tell|inform)\s+(anyone|family|police)\b", 15),
        (r"\bskype\s+hearing|video\s+court\b", 12),
        (r"\b(drug|narcotic|contraband)\s+(case|found|linked)\b", 12),
    ],
    "olx_quickr_scam": [
        (r"\bolx\b", 8), (r"\bquickr\b", 8),
        (r"\barmy\s+(officer|personnel|man)\b", 10),
        (r"\bdefence\s+(officer|personnel)\b", 10),
        (r"\btransfer\s+(fee|charges|advance)\b", 10),
        (r"\badvance\s+payment\b", 9),
        (r"\btoken\s+(amount|money|advance)\b", 10),
        (r"\bregistration\s+(fee|charge|amount)\b", 8),
        (r"\bgoods\s+transport\b", 7),
    ],
    "upi_fraud": [
        (r"\bupi\b", 6), (r"\bgoogle\s*pay|gpay\b", 6),
        (r"\bphonepe\b", 6), (r"\bpaytm\b", 5),
        (r"\bscan\s+(and\s+)?pay|scan\s+qr\b", 8),
        (r"\bcollect\s+request\b", 10),
        (r"\benter\s+(upi|pin)\s+(to\s+)?(receive|get|claim)\b", 15),
        (r"\bsend\s+re?\.?\s*1\s+(to\s+)?(verify|confirm|get)\b", 12),
        (r"\bqr\s+code\s+(scan|pay|send)\b", 8),
        (r"\bcashback.*upi|upi.*cashback\b", 9),
        (r"\brefund.*upi|upi.*refund\b", 10),
    ],
    "loan_app_harassment": [
        (r"\bloan\s+(app|application|approved|offer)\b", 7),
        (r"\binstant\s+loan\b", 8), (r"\bpersonal\s+loan.*approved\b", 8),
        (r"\bno\s+(documents?|kyc|cibil|credit)\s+(required|needed|check)\b", 10),
        (r"\bemi\s+(pending|overdue|default)\b", 8),
        (r"\bcontact\s+(list|gallery|photos)\s+(access|upload|share)\b", 12),
        (r"\bshame\s+(you|family|contacts)\b", 12),
        (r"\brecovery\s+agent\b", 10),
    ],
    "sim_swap_fraud": [
        (r"\bsim\s+(swap|block|expired|upgrade|invalid)\b", 15),
        (r"\bsim\s+(card\s+)?(verif|updat|renew)\b", 12),
        (r"\bmobile\s+number\s+(verif|block|suspend)\b", 10),
        (r"\bjio|airtel|vodafone|vi\s+(sim|number|account)\b", 7),
        (r"\bport\s+(your\s+)?number\b", 8),
        (r"\boutgoing\s+(call|service)\s+(block|suspend)\b", 10),
    ],
    "investment_scam": [
        (r"\bguaranteed\s+(return|profit|income)\b", 12),
        (r"\bdouble\s+your\s+(money|investment)\b", 12),
        (r"\bstock\s+(tip|market|trading).*profit\b", 9),
        (r"\bcrypto(currency)?\s+(invest|profit|return)\b", 9),
        (r"\bwork\s+from\s+home.*earn\b", 8),
        (r"\btask\s+(complet|based)\s+(earn|income|money)\b", 10),
        (r"\btelegram\s+(group|channel)\s+(invest|earn|profit)\b", 12),
        (r"\bMLM|multi.?level.?market\b", 10),
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
    "digital_arrest_scam": "Digital Arrest Scam (UP Police Priority)",
    "olx_quickr_scam": "OLX / Quickr Fraud Pattern",
    "upi_fraud": "UPI Payment Fraud",
    "loan_app_harassment": "Loan App Harassment",
    "sim_swap_fraud": "SIM Swap Fraud",
    "investment_scam": "Fake Investment / Task-Based Scam",
}


def analyze_content(text: str, subject: str = "") -> dict:
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
                m = re.search(pattern, full_text, flags=re.IGNORECASE)
                if m:
                    matches.append(m.group(0))

        cat_score = min(cat_score, 50)
        categories[cat] = {
            "label": CATEGORY_LABELS[cat],
            "matched": cat_score > 0,
            "score": cat_score,
            "matches": matches,
        }
        if cat_score > 0:
            total_score += cat_score
            risk_word = "High" if cat_score >= 15 else "Medium"
            detected_labels.append(f"{CATEGORY_LABELS[cat]} Detected — Risk: {risk_word}")

    overall = min(total_score, 100)
    if overall >= 50:
        level = "Critical"
    elif overall >= 25:
        level = "High"
    elif overall >= 10:
        level = "Medium"
    else:
        level = "Low"

    return {
        "categories": categories,
        "overall_risk_score": overall,
        "risk_level": level,
        "detected_labels": detected_labels,
    }
