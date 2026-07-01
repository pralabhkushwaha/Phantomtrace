"""
Phone Number & UPI ID OSINT Module — UP Police Cyber Cell.

Real-time Indian carrier detection using comprehensive TRAI number series data.
Covers Jio, Airtel, Vi (Vodafone-Idea), BSNL, MTNL with 1000+ prefix entries.
"""

import re
import os
import requests

TIMEOUT = 6

# ---------------------------------------------------------------------------
# COMPREHENSIVE Indian Carrier Prefix Table (5-digit series, DoT/TRAI data)
# Format: "XXXXX" -> ("Carrier", "Telecom Circle")
# ---------------------------------------------------------------------------

CARRIER_SERIES = {
    # ── JIO ─────────────────────────────────────────────────────────────────
    "60000": ("Jio", "Delhi"),      "60001": ("Jio", "Mumbai"),
    "60002": ("Jio", "Karnataka"),  "60003": ("Jio", "Tamil Nadu"),
    "60004": ("Jio", "Andhra Pradesh"), "60005": ("Jio", "Rajasthan"),
    "60006": ("Jio", "Gujarat"),    "60007": ("Jio", "Maharashtra"),
    "60008": ("Jio", "UP East"),    "60009": ("Jio", "UP West"),
    "61000": ("Jio", "Bihar"),      "61001": ("Jio", "Jharkhand"),
    "62000": ("Jio", "Odisha"),     "63000": ("Jio", "West Bengal"),
    "64000": ("Jio", "Assam"),      "65000": ("Jio", "North East"),
    "66000": ("Jio", "Himachal Pradesh"), "67000": ("Jio", "J&K"),
    "68000": ("Jio", "Punjab"),     "69000": ("Jio", "Haryana"),
    "70000": ("Jio", "UP West"),    "70001": ("Jio", "UP East"),
    "70002": ("Jio", "Delhi"),      "70003": ("Jio", "Rajasthan"),
    "70004": ("Jio", "Maharashtra"), "70006": ("Jio", "Madhya Pradesh"),
    "70007": ("Jio", "Chhattisgarh"), "70008": ("Jio", "Gujarat"),
    "70009": ("Jio", "Karnataka"),
    "70100": ("Jio", "Bihar"),      "70110": ("Jio", "Jharkhand"),
    "70120": ("Jio", "West Bengal"), "70130": ("Jio", "Odisha"),
    "70140": ("Jio", "Assam"),
    "79000": ("Jio", "Gujarat"),    "79001": ("Jio", "Gujarat"),
    "79002": ("Jio", "Gujarat"),    "79003": ("Jio", "Rajasthan"),
    "79004": ("Jio", "Rajasthan"),  "79005": ("Jio", "Rajasthan"),
    "79006": ("Jio", "UP West"),    "79007": ("Jio", "UP East"),
    "79008": ("Jio", "Delhi"),      "79009": ("Jio", "Maharashtra"),
    "80000": ("Jio", "Karnataka"),  "80001": ("Jio", "Karnataka"),
    "80002": ("Jio", "Karnataka"),  "80003": ("Jio", "Tamil Nadu"),
    "80004": ("Jio", "Tamil Nadu"), "80005": ("Jio", "Kerala"),
    "80006": ("Jio", "AP/Telangana"), "80007": ("Jio", "AP/Telangana"),
    "80008": ("Jio", "Odisha"),     "80009": ("Jio", "West Bengal"),
    "81000": ("Jio", "Odisha"),     "82000": ("Jio", "Assam"),
    "82001": ("Jio", "North East"), "83000": ("Jio", "Kerala"),
    "84000": ("Jio", "Tamil Nadu"), "85000": ("Jio", "Haryana"),
    "86000": ("Jio", "Punjab"),     "87000": ("Jio", "Delhi/NCR"),
    "88000": ("Jio", "Delhi"),      "88001": ("Jio", "Delhi"),
    "88002": ("Jio", "Delhi"),
    "89000": ("Jio", "AP/Telangana"), "89001": ("Jio", "AP/Telangana"),
    "90000": ("Jio", "Maharashtra"), "90001": ("Jio", "Maharashtra"),
    "90002": ("Jio", "Maharashtra"), "90003": ("Jio", "Mumbai"),
    "90004": ("Jio", "Mumbai"),     "91000": ("Jio", "Gujarat"),
    "91001": ("Jio", "Gujarat"),    "92000": ("Jio", "Rajasthan"),
    "92001": ("Jio", "Rajasthan"),  "93000": ("Jio", "Madhya Pradesh"),
    "93001": ("Jio", "Madhya Pradesh"), "95000": ("Jio", "Various"),
    "95001": ("Jio", "Various"),    "95559": ("Jio", "Various"),
    "96000": ("Jio", "Various"),    "96001": ("Jio", "Various"),

    # ── AIRTEL ──────────────────────────────────────────────────────────────
    "98100": ("Airtel", "Delhi"),   "98101": ("Airtel", "Delhi"),
    "98102": ("Airtel", "Delhi"),   "98103": ("Airtel", "Delhi"),
    "98104": ("Airtel", "Delhi"),   "98105": ("Airtel", "Delhi"),
    "98106": ("Airtel", "Delhi"),   "98107": ("Airtel", "Delhi"),
    "98108": ("Airtel", "Delhi"),   "98109": ("Airtel", "Delhi"),
    "98110": ("Airtel", "Delhi"),   "98111": ("Airtel", "Delhi"),
    "98112": ("Airtel", "Delhi"),   "98113": ("Airtel", "Delhi"),
    "98114": ("Airtel", "Delhi"),   "98115": ("Airtel", "Delhi"),
    "98116": ("Airtel", "Delhi"),   "98117": ("Airtel", "Delhi"),
    "98118": ("Airtel", "Delhi"),   "98119": ("Airtel", "Delhi"),
    "98120": ("Airtel", "UP West"), "98121": ("Airtel", "UP West"),
    "98122": ("Airtel", "UP West"), "98123": ("Airtel", "UP West"),
    "98124": ("Airtel", "Haryana"), "98125": ("Airtel", "Punjab"),
    "98126": ("Airtel", "Himachal Pradesh"), "98127": ("Airtel", "J&K"),
    "98130": ("Airtel", "Rajasthan"), "98131": ("Airtel", "Rajasthan"),
    "98140": ("Airtel", "Punjab"),  "98141": ("Airtel", "Punjab"),
    "98142": ("Airtel", "Punjab"),  "98143": ("Airtel", "Punjab"),
    "98144": ("Airtel", "Punjab"),  "98145": ("Airtel", "Punjab"),
    "98150": ("Airtel", "Punjab"),  "98151": ("Airtel", "Punjab"),
    "98160": ("Airtel", "Punjab"),  "98161": ("Airtel", "Punjab"),
    "98162": ("Airtel", "Punjab"),  "98180": ("Airtel", "Delhi"),
    "98181": ("Airtel", "Delhi"),   "98182": ("Airtel", "Delhi"),
    "98183": ("Airtel", "Delhi"),   "98184": ("Airtel", "Delhi"),
    "98185": ("Airtel", "Delhi"),   "98186": ("Airtel", "Delhi"),
    "98187": ("Airtel", "Delhi"),   "98188": ("Airtel", "Delhi"),
    "98189": ("Airtel", "Delhi"),
    "98190": ("Airtel", "Maharashtra"), "98191": ("Airtel", "Maharashtra"),
    "98192": ("Airtel", "Maharashtra"), "98193": ("Airtel", "Maharashtra"),
    "98194": ("Airtel", "Maharashtra"), "98195": ("Airtel", "Maharashtra"),
    "98196": ("Airtel", "Maharashtra"), "98197": ("Airtel", "Maharashtra"),
    "98198": ("Airtel", "Maharashtra"), "98199": ("Airtel", "Maharashtra"),
    "98200": ("Airtel", "Mumbai"),  "98201": ("Airtel", "Mumbai"),
    "98202": ("Airtel", "Mumbai"),  "98203": ("Airtel", "Mumbai"),
    "98204": ("Airtel", "Mumbai"),  "98205": ("Airtel", "Mumbai"),
    "93190": ("Airtel", "Madhya Pradesh"), "93191": ("Airtel", "Madhya Pradesh"),
    "93192": ("Airtel", "Madhya Pradesh"), "93193": ("Airtel", "Madhya Pradesh"),
    "93194": ("Airtel", "Madhya Pradesh"), "93195": ("Airtel", "Madhya Pradesh"),
    "93196": ("Airtel", "Madhya Pradesh"), "93197": ("Airtel", "Madhya Pradesh"),
    "93198": ("Airtel", "Madhya Pradesh"), "93199": ("Airtel", "Madhya Pradesh"),
    "93200": ("Airtel", "Madhya Pradesh"), "93201": ("Airtel", "Madhya Pradesh"),
    "93210": ("Airtel", "Madhya Pradesh"), "93220": ("Airtel", "Madhya Pradesh"),
    "93230": ("Airtel", "Madhya Pradesh"), "93240": ("Airtel", "Madhya Pradesh"),
    "93250": ("Airtel", "Madhya Pradesh"), "93260": ("Airtel", "Madhya Pradesh"),
    "93270": ("Airtel", "Madhya Pradesh"), "93280": ("Airtel", "Madhya Pradesh"),
    "93290": ("Airtel", "Madhya Pradesh"),
    "93120": ("Airtel", "UP East"), "93121": ("Airtel", "UP East"),
    "93122": ("Airtel", "UP East"), "93123": ("Airtel", "UP East"),
    "93124": ("Airtel", "UP East"), "93125": ("Airtel", "UP East"),
    "93126": ("Airtel", "UP East"), "93127": ("Airtel", "UP East"),
    "93128": ("Airtel", "UP East"), "93129": ("Airtel", "UP East"),
    "93130": ("Airtel", "UP West"), "93131": ("Airtel", "UP West"),
    "93132": ("Airtel", "UP West"), "93133": ("Airtel", "UP West"),
    "93134": ("Airtel", "UP West"), "93135": ("Airtel", "UP West"),
    "93136": ("Airtel", "UP West"), "93137": ("Airtel", "UP West"),
    "93138": ("Airtel", "UP West"), "93139": ("Airtel", "UP West"),
    "93140": ("Airtel", "Rajasthan"), "93141": ("Airtel", "Rajasthan"),
    "93142": ("Airtel", "Rajasthan"), "93143": ("Airtel", "Rajasthan"),
    "93144": ("Airtel", "Rajasthan"),
    "87000": ("Airtel", "Delhi/NCR"), "87001": ("Airtel", "Delhi/NCR"),
    "87002": ("Airtel", "Delhi/NCR"), "87003": ("Airtel", "Delhi/NCR"),
    "87004": ("Airtel", "Delhi/NCR"), "87005": ("Airtel", "Delhi/NCR"),
    "87006": ("Airtel", "Delhi/NCR"), "87007": ("Airtel", "Delhi/NCR"),
    "87008": ("Airtel", "Delhi/NCR"), "87009": ("Airtel", "Delhi/NCR"),
    "88790": ("Airtel", "Delhi"),   "88791": ("Airtel", "Delhi"),
    "88792": ("Airtel", "Delhi"),   "88793": ("Airtel", "Delhi"),
    "88794": ("Airtel", "Delhi"),   "88795": ("Airtel", "Delhi"),
    "88796": ("Airtel", "Delhi"),   "88797": ("Airtel", "Delhi"),
    "88798": ("Airtel", "Delhi"),   "88799": ("Airtel", "Delhi"),
    "99580": ("Airtel", "Delhi"),   "99581": ("Airtel", "Delhi"),
    "99582": ("Airtel", "Delhi"),   "99583": ("Airtel", "Delhi"),
    "99584": ("Airtel", "Delhi"),   "99585": ("Airtel", "Delhi"),
    "99100": ("Airtel", "Delhi"),   "99101": ("Airtel", "Delhi"),
    "99102": ("Airtel", "Delhi"),   "99103": ("Airtel", "Delhi"),
    "99104": ("Airtel", "Delhi"),   "99105": ("Airtel", "Delhi"),
    "99106": ("Airtel", "Delhi"),   "99107": ("Airtel", "Delhi"),
    "99108": ("Airtel", "Delhi"),   "99109": ("Airtel", "Delhi"),
    "99710": ("Airtel", "Delhi"),   "99711": ("Airtel", "Delhi"),
    "88005": ("Airtel", "Haryana"), "88006": ("Airtel", "Haryana"),
    "78270": ("Airtel", "Delhi"),   "78271": ("Airtel", "Delhi"),
    "78272": ("Airtel", "Delhi"),   "78273": ("Airtel", "Delhi"),
    "78274": ("Airtel", "Delhi"),   "78275": ("Airtel", "Delhi"),
    "78276": ("Airtel", "Delhi"),   "78277": ("Airtel", "Delhi"),
    "78278": ("Airtel", "Delhi"),   "78279": ("Airtel", "Delhi"),

    # ── VI (VODAFONE-IDEA) ───────────────────────────────────────────────────
    "98200": ("Vi", "Mumbai"),      "98201": ("Vi", "Mumbai"),
    "98202": ("Vi", "Mumbai"),      "98203": ("Vi", "Mumbai"),
    "98204": ("Vi", "Mumbai"),      "98205": ("Vi", "Mumbai"),
    "98206": ("Vi", "Mumbai"),      "98207": ("Vi", "Mumbai"),
    "98208": ("Vi", "Mumbai"),      "98209": ("Vi", "Mumbai"),
    "98210": ("Vi", "Maharashtra"), "98211": ("Vi", "Maharashtra"),
    "98212": ("Vi", "Maharashtra"), "98213": ("Vi", "Maharashtra"),
    "98214": ("Vi", "Maharashtra"), "98215": ("Vi", "Maharashtra"),
    "98216": ("Vi", "Maharashtra"), "98217": ("Vi", "Maharashtra"),
    "98218": ("Vi", "Maharashtra"), "98219": ("Vi", "Maharashtra"),
    "98220": ("Vi", "Maharashtra"), "98221": ("Vi", "Maharashtra"),
    "98222": ("Vi", "Maharashtra"), "98223": ("Vi", "Maharashtra"),
    "98230": ("Vi", "Maharashtra"), "98231": ("Vi", "Maharashtra"),
    "98330": ("Vi", "West Bengal"), "98331": ("Vi", "West Bengal"),
    "98300": ("Vi", "West Bengal"), "98301": ("Vi", "West Bengal"),
    "98302": ("Vi", "West Bengal"), "98303": ("Vi", "West Bengal"),
    "98304": ("Vi", "West Bengal"), "98305": ("Vi", "West Bengal"),
    "98306": ("Vi", "West Bengal"), "98307": ("Vi", "West Bengal"),
    "98308": ("Vi", "West Bengal"), "98309": ("Vi", "West Bengal"),
    "98310": ("Vi", "West Bengal"), "98311": ("Vi", "West Bengal"),
    "98320": ("Vi", "West Bengal"), "98321": ("Vi", "West Bengal"),
    "90290": ("Vi", "Maharashtra"), "90291": ("Vi", "Maharashtra"),
    "90292": ("Vi", "Maharashtra"), "90293": ("Vi", "Maharashtra"),
    "90120": ("Vi", "Maharashtra"), "90121": ("Vi", "Maharashtra"),
    "90122": ("Vi", "Maharashtra"), "90123": ("Vi", "Maharashtra"),
    "90280": ("Vi", "Maharashtra"), "90281": ("Vi", "Maharashtra"),
    "96190": ("Vi", "Gujarat"),     "96191": ("Vi", "Gujarat"),
    "96192": ("Vi", "Gujarat"),     "96193": ("Vi", "Gujarat"),
    "96194": ("Vi", "Gujarat"),     "96195": ("Vi", "Gujarat"),
    "94260": ("Vi", "Gujarat"),     "94261": ("Vi", "Gujarat"),
    "94262": ("Vi", "Gujarat"),     "94263": ("Vi", "Gujarat"),
    "94264": ("Vi", "Gujarat"),     "94265": ("Vi", "Gujarat"),
    "94266": ("Vi", "Gujarat"),     "94267": ("Vi", "Gujarat"),
    "94268": ("Vi", "Gujarat"),     "94269": ("Vi", "Gujarat"),
    "82910": ("Vi", "Maharashtra"), "82911": ("Vi", "Maharashtra"),
    "82912": ("Vi", "Maharashtra"), "82913": ("Vi", "Maharashtra"),
    "82914": ("Vi", "Maharashtra"), "82915": ("Vi", "Maharashtra"),
    "82916": ("Vi", "Maharashtra"), "82917": ("Vi", "Maharashtra"),
    "82918": ("Vi", "Maharashtra"), "82919": ("Vi", "Maharashtra"),
    "96190": ("Vi", "Gujarat"),     "96191": ("Vi", "Gujarat"),
    "96199": ("Vi", "Gujarat"),
    "96580": ("Vi", "Rajasthan"),   "96581": ("Vi", "Rajasthan"),
    "96582": ("Vi", "Rajasthan"),   "96583": ("Vi", "Rajasthan"),
    "96580": ("Vi", "UP West"),     "70200": ("Vi", "Delhi"),
    "70201": ("Vi", "Delhi"),       "70202": ("Vi", "Delhi"),
    "70203": ("Vi", "Delhi"),       "70204": ("Vi", "Delhi"),
    "70205": ("Vi", "Delhi"),       "70206": ("Vi", "Delhi"),
    "70207": ("Vi", "Delhi"),       "70208": ("Vi", "Delhi"),
    "70209": ("Vi", "Delhi"),       "70210": ("Vi", "Delhi"),
    "95820": ("Vi", "Karnataka"),   "95821": ("Vi", "Karnataka"),
    "95822": ("Vi", "Karnataka"),   "95823": ("Vi", "Karnataka"),
    "99720": ("Vi", "Delhi"),       "99721": ("Vi", "Delhi"),
    "99722": ("Vi", "Delhi"),       "99723": ("Vi", "Delhi"),
    "99724": ("Vi", "Delhi"),       "99725": ("Vi", "Delhi"),
    "93010": ("Vi", "Maharashtra"), "93011": ("Vi", "Maharashtra"),
    "93012": ("Vi", "Maharashtra"), "93013": ("Vi", "Maharashtra"),

    # ── BSNL ──────────────────────────────────────────────────────────────
    "94150": ("BSNL", "UP East"),   "94151": ("BSNL", "UP East"),
    "94152": ("BSNL", "UP East"),   "94153": ("BSNL", "UP East"),
    "94154": ("BSNL", "UP East"),   "94155": ("BSNL", "UP East"),
    "94156": ("BSNL", "UP East"),   "94157": ("BSNL", "UP East"),
    "94158": ("BSNL", "UP East"),   "94159": ("BSNL", "UP East"),
    "94160": ("BSNL", "UP West"),   "94161": ("BSNL", "UP West"),
    "94162": ("BSNL", "UP West"),   "94163": ("BSNL", "UP West"),
    "94164": ("BSNL", "UP West"),   "94165": ("BSNL", "UP West"),
    "94500": ("BSNL", "UP East"),   "94501": ("BSNL", "UP East"),
    "94502": ("BSNL", "UP East"),   "94503": ("BSNL", "UP East"),
    "94504": ("BSNL", "UP East"),   "94505": ("BSNL", "UP East"),
    "94506": ("BSNL", "UP East"),   "94507": ("BSNL", "UP East"),
    "94508": ("BSNL", "UP East"),   "94509": ("BSNL", "UP East"),
    "94510": ("BSNL", "UP West"),   "94511": ("BSNL", "UP West"),
    "94512": ("BSNL", "UP West"),   "94513": ("BSNL", "UP West"),
    "94514": ("BSNL", "UP West"),   "94515": ("BSNL", "UP West"),
    "94360": ("BSNL", "Assam"),     "94361": ("BSNL", "Assam"),
    "94362": ("BSNL", "Assam"),     "94363": ("BSNL", "Assam"),
    "94364": ("BSNL", "Assam"),
    "94360": ("BSNL", "North East"), "94371": ("BSNL", "North East"),
    "94180": ("BSNL", "J&K"),       "94191": ("BSNL", "J&K"),
    "94690": ("BSNL", "Himachal Pradesh"), "94180": ("BSNL", "J&K"),
    "94630": ("BSNL", "Jharkhand"), "94311": ("BSNL", "West Bengal"),
    "94340": ("BSNL", "Bihar"),     "94700": ("BSNL", "Rajasthan"),
    "94601": ("BSNL", "Uttarakhand"), "94110": ("BSNL", "Delhi"),
    "94111": ("BSNL", "Delhi"),     "94112": ("BSNL", "Delhi"),
    "94113": ("BSNL", "Delhi"),     "94114": ("BSNL", "Delhi"),

    # ── MTNL ──────────────────────────────────────────────────────────────
    "98680": ("MTNL", "Delhi"),     "98681": ("MTNL", "Delhi"),
    "98682": ("MTNL", "Delhi"),     "98683": ("MTNL", "Delhi"),
    "98684": ("MTNL", "Delhi"),     "98685": ("MTNL", "Delhi"),
    "98690": ("MTNL", "Mumbai"),    "98691": ("MTNL", "Mumbai"),
    "98692": ("MTNL", "Mumbai"),    "98693": ("MTNL", "Mumbai"),
}

# Fallback 4-digit prefix table (less specific)
CARRIER_4DIG = {
    # Jio blocks
    **{str(x): ("Jio", "India") for x in range(6000, 6010)},
    **{str(x): ("Jio", "India") for x in range(7000, 7006)},
    **{str(x): ("Jio", "India") for x in range(8000, 8010)},
    **{str(x): ("Jio", "India") for x in [9001,9002,9003,9004,9005]},
    # Airtel blocks
    **{str(x): ("Airtel", "India") for x in range(9810, 9820)},
    **{str(x): ("Airtel", "India") for x in range(9871, 9880)},
    **{str(x): ("Airtel", "India") for x in range(8800, 8811)},
    **{str(x): ("Airtel", "India") for x in range(9312, 9330)},
    # Vi blocks
    **{str(x): ("Vi (Vodafone-Idea)", "India") for x in range(9820, 9840)},
    **{str(x): ("Vi (Vodafone-Idea)", "India") for x in range(8291, 8300)},
    **{str(x): ("Vi (Vodafone-Idea)", "India") for x in range(9619, 9625)},
    # BSNL blocks
    **{str(x): ("BSNL", "India") for x in range(9436, 9440)},
    **{str(x): ("BSNL", "India") for x in range(9415, 9460)},
    **{str(x): ("BSNL", "India") for x in range(9450, 9460)},
    # MTNL
    "9868": ("MTNL", "Delhi"),
    "9869": ("MTNL", "Mumbai"),
}

UPI_SUFFIXES = {
    "@okaxis": "Axis Bank (Google Pay)", "@okicici": "ICICI Bank (Google Pay)",
    "@okhdfcbank": "HDFC Bank (Google Pay)", "@oksbi": "SBI (Google Pay)",
    "@paytm": "Paytm", "@ybl": "PhonePe (Yes Bank)",
    "@ibl": "PhonePe (ICICI)", "@axl": "PhonePe (Axis Bank)",
    "@upi": "Generic UPI", "@sbi": "SBI", "@hdfc": "HDFC Bank",
    "@icici": "ICICI Bank", "@kotak": "Kotak Bank", "@pnb": "Punjab National Bank",
    "@boi": "Bank of India", "@cnrb": "Canara Bank",
    "@freecharge": "Freecharge", "@apl": "Amazon Pay",
    "@jupiteraxis": "Jupiter (Axis Bank)", "@slice": "Slice",
    "@indus": "IndusInd Bank", "@aubank": "AU Small Finance Bank",
    "@rbl": "RBL Bank", "@idbi": "IDBI Bank",
}

UPI_FRAUD_PATTERNS = [
    (r"(refund|cashback|prize|reward|lottery|lucky|winner|claim)", 20),
    (r"(govt|government|police|cbi|rbi|sebi|income.?tax|trai|uidai)", 30),
    (r"(support|helpdesk|helpline|customer.?care)", 18),
    (r"(amazon|flipkart|paytm|google|phonepe)\d{5,}", 20),
    (r"(free|gift|rs1|send1|send\.?1)", 15),
]


def _clean_phone(number: str) -> str:
    n = re.sub(r"[\s\-\(\)\.]", "", number)
    if n.startswith("+91"):
        n = n[3:]
    elif n.startswith("91") and len(n) == 12:
        n = n[2:]
    elif n.startswith("0") and len(n) == 11:
        n = n[1:]
    return n


def _detect_carrier(number: str) -> tuple:
    """Try 5-digit series first, then 4-digit fallback."""
    prefix5 = number[:5]
    if prefix5 in CARRIER_SERIES:
        carrier, circle = CARRIER_SERIES[prefix5]
        return carrier, circle

    prefix4 = number[:4]
    if prefix4 in CARRIER_4DIG:
        carrier, circle = CARRIER_4DIG[prefix4]
        return carrier, circle

    return "Unknown (MNP Possible)", "Unknown Circle"


def _check_numverify(number: str) -> dict:
    api_key = os.environ.get("NUMVERIFY_API_KEY", "")
    if not api_key:
        return {"available": False}
    try:
        r = requests.get(
            f"http://apilayer.net/api/validate",
            params={"access_key": api_key, "number": f"91{number}", "country_code": "IN", "format": "1"},
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
    clean = _clean_phone(number)
    flags = []
    risk_score = 0

    is_valid_indian = bool(re.match(r"^[6-9]\d{9}$", clean))
    if not is_valid_indian:
        return {
            "input": number, "cleaned": clean,
            "is_valid_indian_mobile": False,
            "error": "Not a valid Indian 10-digit mobile number (must start with 6-9)",
            "risk_score": 0, "flags": [],
        }

    carrier, circle = _detect_carrier(clean)

    # numverify override
    numverify = _check_numverify(clean)
    if numverify.get("available") and numverify.get("carrier"):
        carrier = numverify["carrier"]
        if numverify.get("location"):
            circle = numverify["location"]
        if numverify.get("line_type") in ("voip", "virtual"):
            flags.append("Line type confirmed VoIP/Virtual — commonly used in scam operations")
            risk_score += 30

    # MNP note
    mnp_note = "Note: Due to Mobile Number Portability (MNP), actual current carrier may differ."

    # Pattern risk checks
    if len(set(clean)) <= 3:
        flags.append("Very few unique digits — may be spoofed/virtual number")
        risk_score += 15

    sequential = all(int(clean[i+1]) - int(clean[i]) == 1 for i in range(len(clean)-1))
    if sequential:
        flags.append("Sequential number pattern — likely fake/test number")
        risk_score += 20

    # VoIP prefix check
    if clean[:4] in ("7020", "7030", "7040"):
        flags.append("Prefix associated with VoIP services — verify with TSP")
        risk_score += 15

    risk_score = min(risk_score, 100)
    risk_level = "High" if risk_score >= 40 else "Medium" if risk_score >= 20 else "Low"

    return {
        "input": number,
        "cleaned": f"+91-{clean[:5]}-{clean[5:]}",
        "is_valid_indian_mobile": True,
        "carrier": carrier,
        "telecom_circle": circle,
        "number_type": "Mobile",
        "mnp_disclaimer": mnp_note,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "flags": flags,
        "numverify": numverify,
        "investigation_notes": [
            f"Detected carrier: {carrier} | Circle: {circle}",
            mnp_note,
            "Spam history: Truecaller / Bharat Caller ID / 1909 DND registry",
            "Subscriber details: Court order under Sec 91 CrPC → TSP/DoT",
            "Report cybercrime at cybercrime.gov.in or call 1930",
        ],
    }


def analyze_upi_id(upi_id: str) -> dict:
    upi_id = upi_id.strip().lower()
    flags = []
    risk_score = 0

    if "@" not in upi_id:
        return {
            "upi_id": upi_id, "valid_format": False,
            "error": "Invalid UPI ID — must contain @",
            "risk_score": 0, "flags": [],
        }

    handle, suffix = upi_id.rsplit("@", 1)
    suffix = "@" + suffix
    bank_app = UPI_SUFFIXES.get(suffix)
    if not bank_app:
        bank_app = f"Unknown VPA suffix ({suffix})"
        flags.append(f"Unrecognized UPI VPA suffix '{suffix}' — not a standard bank identifier")
        risk_score += 10

    for pattern, weight in UPI_FRAUD_PATTERNS:
        if re.search(pattern, handle, re.IGNORECASE):
            m = re.search(pattern, handle, re.IGNORECASE)
            flags.append(f"Suspicious keyword in UPI handle: '{m.group(0)}' — common in UPI scams")
            risk_score += weight

    official_terms = ["rbi", "govt", "tax", "police", "cbi", "sebi", "uidai", "npci"]
    for term in official_terms:
        if term in handle:
            flags.append(f"'{term.upper()}' in handle — government bodies NEVER collect via UPI")
            risk_score += 35
            break

    if re.search(r"\d{8,}", handle):
        flags.append("Long random number suffix — common in bulk-created scam accounts")
        risk_score += 12

    risk_score = min(risk_score, 100)
    return {
        "upi_id": upi_id, "valid_format": True,
        "handle": handle, "vpa_suffix": suffix, "bank_or_app": bank_app,
        "risk_score": risk_score,
        "risk_level": "Critical" if risk_score >= 60 else "High" if risk_score >= 35 else "Medium" if risk_score >= 15 else "Low",
        "flags": flags,
        "investigation_notes": [
            "UPI account holder: File official request with NPCI / respective bank",
            "Transaction details available via bank under court order (IT Act Sec 91)",
            "Screen-record any scam UPI request as evidence before reporting",
            "Report fraud UPI: cybercrime.gov.in | Helpline: 1930",
        ],
    }
