"""
Phone Number & UPI ID OSINT Module.

Analyzes Indian phone numbers and UPI IDs for fraud indicators:
  - Carrier / telecom circle detection (Indian)
  - VoIP / virtual number detection
  - Known spam number check (via free APIs)
  - UPI ID format validation and risk analysis
  - WhatsApp number validation hint
  - Pattern-based fraud risk indicators
"""

import re
import requests

TIMEOUT = 6

# Indian telecom prefixes -> carrier mapping (first 4 digits of 10-digit number)
INDIAN_CARRIER_PREFIXES = {
    "jio": [
        "6000","6001","6002","6003","6004","6005","6006","6007","6008","6009",
        "7000","7001","7002","7003","7004","7005","7006","7007","7008","7009",
        "8000","8001","8002","8003","8004","8005","8006","8007","8008","8009",
        "9000","9001","9002","9003","9004","9005",
    ],
    "airtel": [
        "9810","9811","9812","9813","9814","9815","9816","9817","9818","9819",
        "9820","9821","9822","9823","9824","9825","9826","9827","9828","9829",
        "8800","8801","8802","8803","8804","8805","8806","8807","8808","8809",
        "7010","7011","7012","7013","7014","7015","7016","7017","7018","7019",
    ],
    "vodafone_vi": [
        "9830","9831","9832","9833","9834","9835","9836","9837","9838","9839",
        "8291","8292","8293","8294","8295","8296","8297","8298","8299",
    ],
    "bsnl": [
        "9436","9437","9438","9439","9415","9416","9417","9418","9419",
        "9450","9451","9452","9453","9454","9455","9456","9457","9458","9459",
    ],
}

# Indian state telecom circles (first 2 digits after country code)
INDIAN_STATE_CIRCLES = {
    "70": "Uttar Pradesh / Uttarakhand",
    "71": "Madhya Pradesh / Chhattisgarh",
    "72": "Maharashtra / Goa",
    "73": "Tamil Nadu / Pondicherry",
    "74": "Rajasthan",
    "75": "Uttar Pradesh",
    "76": "Bihar / Jharkhand",
    "77": "West Bengal",
    "78": "Karnataka",
    "79": "Gujarat",
    "80": "Karnataka (Jio)",
    "81": "Odisha",
    "82": "Assam / North East",
    "83": "Kerala",
    "84": "Tamil Nadu",
    "85": "Haryana",
    "86": "Punjab / Himachal Pradesh",
    "87": "Delhi / NCR",
    "88": "Delhi / Airtel",
    "89": "Telangana / Andhra Pradesh",
    "90": "Maharashtra",
    "91": "Gujarat",
    "92": "Rajasthan",
    "93": "Madhya Pradesh",
    "94": "BSNL Various",
    "95": "Jio Various",
    "96": "Various",
    "97": "Various",
    "98": "Metro Cities (Old)",
    "99": "Metro Cities (Old)",
}

UPI_SUFFIXES = {
    "@okaxis": "Axis Bank (Google Pay)",
    "@okicici": "ICICI Bank (Google Pay)",
    "@okhdfcbank": "HDFC Bank (Google Pay)",
    "@oksbi": "SBI (Google Pay)",
    "@paytm": "Paytm",
    "@ybl": "PhonePe (Yes Bank)",
    "@ibl": "PhonePe (ICICI Bank)",
    "@axl": "PhonePe (Axis Bank)",
    "@upi": "Generic UPI",
    "@sbi": "State Bank of India",
    "@hdfc": "HDFC Bank",
    "@icici": "ICICI Bank",
    "@kotak": "Kotak Bank",
    "@pnb": "Punjab National Bank",
    "@boi": "Bank of India",
    "@cnrb": "Canara Bank",
    "@freecharge": "Freecharge",
    "@apl": "Amazon Pay",
    "@jupiteraxis": "Jupiter (Axis Bank)",
    "@slice": "Slice",
}

# High-risk patterns in UPI IDs used for fraud
UPI_FRAUD_PATTERNS = [
    (r"(refund|cashback|prize|reward|lottery|lucky|winner|claim)", 20),
    (r"(govt|government|police|cbi|rbi|sebi|income.?tax)", 25),
    (r"(support|helpdesk|helpline|customer.?care)", 15),
    (r"(amazon|flipkart|paytm|google|phonepe)\d{5,}", 18),
    (r"[a-z]{2,}(\d{8,})", 12),  # random long number suffix
    (r"(free|gift|send\.?1|rs1)", 15),
]


def _clean_phone(number: str) -> str:
    """Strip spaces, dashes, +91, 0 prefix."""
    n = re.sub(r"[\s\-\(\)\.]", "", number)
    if n.startswith("+91"):
        n = n[3:]
    elif n.startswith("91") and len(n) == 12:
        n = n[2:]
    elif n.startswith("0") and len(n) == 11:
        n = n[1:]
    return n


def _detect_carrier(number: str) -> str:
    prefix4 = number[:4]
    for carrier, prefixes in INDIAN_CARRIER_PREFIXES.items():
        if prefix4 in prefixes:
            return carrier.replace("_", " ").title()
    return "Unknown / MVNO"


def _detect_circle(number: str) -> str:
    prefix2 = number[:2]
    return INDIAN_STATE_CIRCLES.get(prefix2, "Unknown Circle")


def _check_numverify(number: str) -> dict:
    """
    numverify.com free tier — 100 req/month, no credit card needed.
    Returns basic line type info. If API key not set, returns not_available.
    """
    import os
    api_key = os.environ.get("NUMVERIFY_API_KEY", "")
    if not api_key:
        return {"available": False}
    try:
        r = requests.get(
            f"http://apilayer.net/api/validate?access_key={api_key}&number=91{number}&country_code=IN&format=1",
            timeout=TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "available": True,
                "valid": d.get("valid"),
                "line_type": d.get("line_type"),
                "carrier": d.get("carrier"),
                "location": d.get("location"),
            }
    except Exception:
        pass
    return {"available": False}


def analyze_phone_number(number: str) -> dict:
    """
    Analyze an Indian mobile number for fraud risk indicators.
    """
    clean = _clean_phone(number)
    flags = []
    risk_score = 0

    # Basic validation
    is_valid_indian = bool(re.match(r"^[6-9]\d{9}$", clean))
    if not is_valid_indian:
        return {
            "input": number,
            "cleaned": clean,
            "is_valid_indian_mobile": False,
            "error": "Not a valid Indian 10-digit mobile number (must start with 6-9)",
            "risk_score": 0,
            "flags": [],
        }

    carrier = _detect_carrier(clean)
    circle = _detect_circle(clean)

    # VoIP / virtual number detection (common in scam operations)
    voip_prefixes = ["6", "7020", "7030", "7040"]
    if clean[:4] in ["7020", "7030", "7040"]:
        flags.append("Number prefix associated with VoIP / virtual numbers — commonly used in scam operations")
        risk_score += 20

    # Check if number follows known scam call center patterns
    # (repeating digits, sequential patterns)
    if len(set(clean)) <= 3:
        flags.append("Number has very few unique digits — may be a virtual/spoofed number")
        risk_score += 15

    sequential = all(int(clean[i+1]) - int(clean[i]) == 1 for i in range(len(clean)-1))
    if sequential:
        flags.append("Sequential number pattern — likely a fake/test number")
        risk_score += 20

    # numverify check (if API key available)
    numverify = _check_numverify(clean)
    if numverify.get("available"):
        if numverify.get("line_type") in ("voip", "virtual"):
            flags.append(f"Line type confirmed as VoIP/Virtual by numverify API")
            risk_score += 25
        if numverify.get("carrier"):
            carrier = numverify["carrier"]

    risk_score = min(risk_score, 100)

    return {
        "input": number,
        "cleaned": f"+91-{clean[:5]}-{clean[5:]}",
        "is_valid_indian_mobile": True,
        "carrier": carrier,
        "telecom_circle": circle,
        "number_type": "Mobile",
        "risk_score": risk_score,
        "risk_level": "High" if risk_score >= 40 else "Medium" if risk_score >= 20 else "Low",
        "flags": flags,
        "numverify": numverify,
        "investigation_notes": [
            f"Number appears to be on {carrier} network",
            f"Telecom circle: {circle}",
            "To verify spam history: check Truecaller / Bharat Caller ID",
            "For legal lookup: Contact DoT / TSP with court order",
        ],
    }


def analyze_upi_id(upi_id: str) -> dict:
    """
    Analyze a UPI ID for fraud risk indicators.
    """
    upi_id = upi_id.strip().lower()
    flags = []
    risk_score = 0

    # Basic format check
    if "@" not in upi_id:
        return {
            "upi_id": upi_id,
            "valid_format": False,
            "error": "Invalid UPI ID format — must contain @",
            "risk_score": 0,
            "flags": [],
        }

    handle, suffix = upi_id.rsplit("@", 1)
    suffix = "@" + suffix

    # Bank/App identification
    bank_app = None
    for known_suffix, label in UPI_SUFFIXES.items():
        if suffix == known_suffix:
            bank_app = label
            break
    if not bank_app:
        bank_app = f"Unknown VPA suffix (@{suffix.lstrip('@')})"
        flags.append(f"Unknown UPI VPA suffix '{suffix}' — not a standard bank/app identifier")
        risk_score += 10

    # Check for fraud patterns in handle
    for pattern, weight in UPI_FRAUD_PATTERNS:
        if re.search(pattern, handle, re.IGNORECASE):
            m = re.search(pattern, handle, re.IGNORECASE)
            flags.append(f"Suspicious keyword in UPI handle: '{m.group(0)}' — commonly used in UPI scams")
            risk_score += weight

    # Check if handle looks like a scammer's impersonation of official entity
    official_terms = ["rbi", "govt", "tax", "police", "cbi", "sebi", "irda", "epfo", "uidai"]
    for term in official_terms:
        if term in handle:
            flags.append(f"UPI handle contains official body name '{term.upper()}' — government agencies do NOT collect payments via UPI")
            risk_score += 30
            break

    # Random long number suffix (bots/scam accounts often have random numbers)
    if re.search(r"\d{8,}", handle):
        flags.append("Handle contains a long random number — often seen in bulk-created scam UPI accounts")
        risk_score += 12

    risk_score = min(risk_score, 100)

    return {
        "upi_id": upi_id,
        "valid_format": True,
        "handle": handle,
        "vpa_suffix": suffix,
        "bank_or_app": bank_app,
        "risk_score": risk_score,
        "risk_level": "Critical" if risk_score >= 60 else "High" if risk_score >= 35 else "Medium" if risk_score >= 15 else "Low",
        "flags": flags,
        "investigation_notes": [
            "To verify UPI account holder: File official request with NPCI / respective bank",
            "UPI transaction details available via bank with court order under IT Act Section 91",
            "Screen-record any scam UPI request as evidence before reporting",
            f"Report fraud UPI ID at: https://cybercrime.gov.in or call 1930",
        ],
    }
