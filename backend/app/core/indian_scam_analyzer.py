"""
Indian Cyber Fraud Pattern Analyzer — UP Police Cyber Cell.
Dedicated high-accuracy detection engine for India-specific cyber crimes.

Coverage (all patterns in English):
  1.  Digital Arrest Scam        — CBI/ED/TRAI/Interpol impersonation
  2.  UPI Payment Fraud          — QR/PIN tricks on Google Pay, PhonePe, Paytm
  3.  KYC / Banking Fraud        — Fake SBI/HDFC/ICICI/RBI alerts
  4.  WhatsApp APK Scam          — Remote-access malware distribution
  5.  SIM Swap / Port Fraud      — Mobile number hijacking
  6.  Loan App Harassment        — Predatory lending + data threats
  7.  OLX / Classifieds Scam     — Army/defence seller impersonation
  8.  Investment / Trading Scam  — Telegram groups, guaranteed returns
  9.  OTP / Credential Phishing  — Extracting PINs, passwords, OTPs
 10.  Fear / Authority Pressure  — Court notices, arrest threats
 11.  Urgency Pressure           — Time-limit manipulation
 12.  KYC Expiry Fraud           — Aadhaar/PAN expiry hooks
 13.  Fake Job / Task Scam       — Work-from-home earning scams

Each pattern list is (regex, weight, evidence_label).
"""

import re
from typing import Dict, List, Tuple

# ---------------------------------------------------------------------------
# Pattern Database
# ---------------------------------------------------------------------------

SCAM_PATTERNS: Dict[str, dict] = {

    "digital_arrest_scam": {
        "label": "Digital Arrest Scam",
        "description": (
            "Impersonation of CBI, ED, Narcotics, TRAI, or Interpol officers claiming "
            "the victim is under 'digital arrest' — a major UP Police Cyber Cell priority."
        ),
        "severity": "critical",
        "patterns": [
            (r"(?i)\b(CBI|Central\s+Bureau\s+of\s+Investigation)\b", 18, "CBI mention"),
            (r"(?i)\b(Enforcement\s+Directorate|ED\s+officer)\b", 18, "ED mention"),
            (r"(?i)\b(Narcotics\s+Control\s+Bureau|NCB\s+officer|narcotics\s+(case|department))\b", 18, "NCB mention"),
            (r"(?i)\b(TRAI|Telecom\s+Regulatory)\b", 14, "TRAI impersonation"),
            (r"(?i)\b(Interpol|INTERPOL)\b", 20, "Interpol mention"),
            (r"(?i)\bdigital\s+arrest\b", 40, "Digital arrest phrase"),
            (r"(?i)\b(you\s+(are|have\s+been)\s+(arrested|detained|under\s+arrest))\b", 30, "Arrest claim"),
            (r"(?i)\b(money\s+laundering|hawala|drug\s+(trafficking|racket|case))\b", 20, "Money laundering/drug accusation"),
            (r"(?i)\b(your\s+)?(aadhaar|aadhar)\s+(is\s+)?(linked|used|involved|found|detected)\b", 15, "Aadhaar link accusation"),
            (r"(?i)\b(warrant|summons)\s+(against|issued|served|for)\s+(you|your)\b", 20, "Warrant issued"),
            (r"(?i)\bdo\s+not\s+(tell|inform|contact|call)\s+anyone\b", 20, "Isolation instruction"),
            (r"(?i)\b(stay|remain|be)\s+on\s+(call|video|line)\b", 18, "Stay on call order"),
            (r"(?i)\bdo\s+not\s+disconnect\b", 15, "Do not disconnect"),
            (r"(?i)\b(FIR|case)\s+(number|no\.?)\s*[\d-]+\s*(registered|filed)?\s*(against\s+you)?\b", 15, "Fake FIR number"),
            (r"(?i)\b(your\s+)?(bank\s+account|accounts?)\s+(will\s+be|has\s+been|are\s+being)\s+(frozen|blocked|seized|attached)\b", 18, "Account freezing threat"),
            (r"(?i)\b(officer|inspector|commissioner|detective)\s+(speaking|here|calling|on\s+line)\b", 12, "Officer claim"),
            (r"(?i)\bcybercrime\s+(unit|police|department|cell)\b", 10, "Cybercrime unit mention"),
            (r"(?i)\bIncome\s+Tax\s+(Department|Officer|Notice|Raid)\b", 15, "Income Tax impersonation"),
        ],
    },

    "upi_fraud": {
        "label": "UPI Payment Fraud",
        "description": (
            "Victim tricked into sending money by accepting fake 'collect money' UPI requests, "
            "entering PIN after scanning QR codes, or approving fraudulent transactions."
        ),
        "severity": "critical",
        "patterns": [
            (r"(?i)\b(enter|share|type|provide)\s+(your\s+)?UPI\s+(PIN|password|mpin)\b", 35, "UPI PIN request"),
            (r"(?i)\b(scan|click)\s+(this|on\s+this|the)\s+QR\s+code\s+(to\s+)?(receive|get|collect|claim)\b", 30, "QR-to-receive trick"),
            (r"(?i)\bQR\s+code\s+(se|ke|for|to)\s+(paise|money|cash|amount)\s+(milenge|receive|get)\b", 25, "QR money receive"),
            (r"(?i)\b(refund|cashback|prize|reward|winning)\s+(of\s+)?Rs\.?\s*[\d,]+\s+(is\s+)?(pending|ready|waiting|approved)\b", 22, "Fake refund pending"),
            (r"(?i)\b(Google\s+Pay|GPay|PhonePe|Paytm|BHIM|UPI)\s+(request|payment|collect)\s+(sent|waiting|pending|ready)\b", 20, "UPI request sent"),
            (r"(?i)\bcollect\s+(money|payment|cash|prize)\s+(via|through|on|using)\s+(UPI|QR|Google\s+Pay|PhonePe|Paytm)\b", 22, "Collect via UPI"),
            (r"(?i)\b(approve|accept|confirm)\s+(the|this|your)\s+(UPI|payment|transaction|collect)\s+request\b", 20, "Approve UPI request"),
            (r"(?i)\breceive\s+Rs\.?\s*[\d,]+\b.{0,40}(click|scan|enter|approve)\b", 22, "Receive then click"),
            (r"(?i)\b(payment|transaction)\s+(failed|rejected)\b.{0,60}\b(re-?send|send\s+again|retry)\b", 18, "Transaction retry trick"),
            (r"(?i)\bUPI\s+ID\s*:\s*[\w.\-@]+\b", 10, "UPI ID shared"),
            (r"(?i)\b(send|transfer)\s+Rs\.?\s*[\d,]+\s+(to\s+verify|for\s+verification|as\s+(token|advance|deposit))\b", 25, "Send money to verify"),
        ],
    },

    "kyc_expiry_fraud": {
        "label": "KYC / Bank Account Fraud",
        "description": (
            "Fake KYC expiry, account suspension, or RBI/NPCI compliance notices from "
            "impersonated Indian banks (SBI, HDFC, ICICI, Axis, PNB etc.)."
        ),
        "severity": "high",
        "patterns": [
            (r"(?i)\bKYC\s+(expir\w+|update\s+required|verification\s+pending|not\s+complet\w+)\b", 28, "KYC expiry/update"),
            (r"(?i)\b(re-?KYC|e-?KYC|video\s+KYC)\s+(complet\w+|pending|required|urgent)\b", 25, "Re-KYC request"),
            (r"(?i)\b(your\s+)?(account|bank\s+account)\s+(will\s+be|has\s+been|is\s+being|may\s+be)\s+(block\w+|suspend\w+|frozen|deactivat\w+|closed)\b", 25, "Account suspension threat"),
            (r"(?i)\b(SBI|HDFC|ICICI|Axis\s+Bank|PNB|Bank\s+of\s+India|Kotak|Yes\s+Bank|Canara|Union\s+Bank|IndusInd)\b.{0,80}\b(alert|notice|update|verification|urgent)\b", 18, "Bank impersonation"),
            (r"(?i)\b(RBI|Reserve\s+Bank|NPCI|UIDAI)\s+(directive|mandate|notice|compliance|circular|regulation)\b", 20, "RBI/NPCI impersonation"),
            (r"(?i)\b(verify|update|complete|submit)\s+(your\s+)?(Aadhaar|PAN|KYC|account\s+details|bank\s+details)\s+(now|immediately|urgently)?\b", 18, "Verify Aadhaar/PAN"),
            (r"(?i)\blink\s+(your\s+)?(Aadhaar|PAN)\s+(with|to)\s+(bank|account)\b", 15, "Link Aadhaar to bank"),
            (r"(?i)\b(within\s+\d+\s+hours?|within\s+\d+\s+minutes?|immediately|urgent)\b.{0,60}\b(account|number|card|service)\s+will\s+be\b", 18, "Urgency + account threat"),
            (r"(?i)\bcustomer\s+(care|service)\s+(number|helpline|no\.?)\s*[:\-]?\s*\+?91?\s*[\d\s-]{8,}\b", 15, "Fake customer care number"),
            (r"(?i)\b(net\s*banking|internet\s+banking)\s+(login|credentials|username|password)\s+(re-?set|update|verify|enter)\b", 22, "Net banking credentials"),
            (r"(?i)\bVPA\s+(block\w+|verify\w+|expir\w+)\b", 18, "VPA blockage"),
            (r"(?i)\bUPI\s+(ID\s+)?(block\w+|suspend\w+|deactivat\w+)\b", 18, "UPI block"),
        ],
    },

    "whatsapp_apk_scam": {
        "label": "WhatsApp APK / Remote Access Scam",
        "description": (
            "Malicious APK files distributed as fake bank, government, or customer-care apps — "
            "leads to remote access takeover of victim's device."
        ),
        "severity": "critical",
        "patterns": [
            (r"(?i)\bdownload\s+(this|the|our)\s+(app|application|apk|software)\b", 28, "Download app instruction"),
            (r"(?i)\binstall\s+(this|the|our)\s+(app|application|software|tool|apk)\b", 25, "Install app instruction"),
            (r"(?i)\.apk\b", 35, "APK file reference"),
            (r"(?i)\b(share|enable|allow)\s+(screen|your\s+screen|screen\s+share)\b", 22, "Screen share request"),
            (r"(?i)\b(AnyDesk|TeamViewer|QuickSupport|AirDroid|iMyFone|RemotePC|RustDesk)\b", 35, "Remote access tool mentioned"),
            (r"(?i)\bremote\s+(access|control|session|assistance|support)\b", 22, "Remote access request"),
            (r"(?i)\b(video\s+call|screen)\b.{0,40}\b(show|verify|check|display)\s+(your\s+)?(account|bank|card|screen)\b", 18, "Video verify scam"),
            (r"(?i)\b(SBI|HDFC|ICICI|RBI|government|Gov\.?in)\s+(official\s+)?(app|application)\s+(link|download|here|below)\b", 22, "Fake official app"),
            (r"(?i)\bclick\s+(here|on\s+(this|the)\s+link)\s+to\s+(install|download|get)\s+(the\s+)?(app|apk)\b", 25, "Click to install"),
            (r"(?i)\bWhatsApp\s+(forward|file|attachment|link)\b.{0,60}\b(install|download|apk|app)\b", 20, "WhatsApp APK forward"),
            (r"(?i)\b(9\d{9})\s+.{0,30}(send|forward)\s+(file|apk|link|attachment)\b", 15, "Number + file sharing"),
        ],
    },

    "sim_swap_fraud": {
        "label": "SIM Swap / Port Fraud",
        "description": (
            "Fraudulent SIM upgrade, porting, or replacement requests to hijack the victim's "
            "mobile number and gain OTP access to bank accounts."
        ),
        "severity": "high",
        "patterns": [
            (r"(?i)\bSIM\s+(upgrade|swap|block|re-?issu\w+|activation|replacement)\b", 28, "SIM swap/upgrade"),
            (r"(?i)\b(port\s+(your\s+)?(number|SIM)|MNP\s+(request|port)|number\s+porting)\b", 28, "Number porting"),
            (r"(?i)\bTRAI\s+(regulation|notice|compliance|directive|order)\b", 20, "TRAI order"),
            (r"(?i)\byour\s+(mobile\s+)?number\s+(will\s+be\s+)?(block\w+|disconnect\w+|suspend\w+|deactivat\w+)\b", 22, "Number suspension threat"),
            (r"(?i)\b(Airtel|Jio|BSNL|Vi\b|Vodafone|Idea)\s+(representative|executive|customer\s+care|official|team)\b", 16, "Telecom impersonation"),
            (r"(?i)\bsend\s+(SMS|message)\s+(1900|PORT|to\s+\d{4})\b", 22, "Port SMS instruction"),
            (r"(?i)\bgenerate\s+(OTP|one-?time\s+password)\s+(on|at|from)\s+(old|current|existing|your)\s+SIM\b", 25, "OTP on old SIM"),
            (r"(?i)\bnew\s+SIM\s+(card\s+)?(activat\w+|deliver\w+|dispatch\w+|sent)\b", 15, "New SIM activation"),
            (r"(?i)\bcall\s+(dropp\w+|fail\w+|disconnect\w+)\b.{0,40}\bSIM\b", 15, "Call drop + SIM"),
        ],
    },

    "loan_app_harassment": {
        "label": "Loan App Harassment",
        "description": (
            "Predatory instant loan apps using data threats (contacts, photos, gallery) "
            "to coerce repayment — common in UP cybercrime complaints."
        ),
        "severity": "high",
        "patterns": [
            (r"(?i)\b(recovery\s+agent|field\s+agent|agent\s+visit)\s+(will|is\s+being|has\s+been)\s+(sent|dispatched|assigned)\b", 25, "Recovery agent threat"),
            (r"(?i)\blegal\s+(action|proceedings|notice)\s+(will\s+be\s+)?(initiat\w+|taken|filed)\s+(against\s+you)?\b", 22, "Legal action threat"),
            (r"(?i)\b(access|use|misuse|leak|share|expose|publish)\s+(your\s+)?(contact\s+list|contacts|phone\s+book|gallery|photos?|images?|call\s+log)\b", 30, "Data exposure threat"),
            (r"(?i)\b(inform|notify|contact|message|call)\s+(your\s+)?(family|relatives|employer|boss|manager|contacts|friends|colleagues)\b", 25, "Inform contacts threat"),
            (r"(?i)\b(EMI|loan|installment)\s+(overdue|pending|default\w+|missed|not\s+paid)\b", 18, "Loan default"),
            (r"(?i)\binstant\s+(loan|cash|credit|money)\s+(approved|offer|available|disburse)\b", 15, "Instant loan hook"),
            (r"(?i)\bRs\.?\s*[\d,]+\s+(penalty|fine|processing\s+fee|late\s+charge)\s+(per\s+(day|hour))?\b", 18, "Penalty charges"),
            (r"(?i)\b(arrest|FIR|police\s+complaint)\s+will\s+(be\s+)?(filed|register\w+)\s+(against\s+you)?\b", 22, "Arrest/FIR threat"),
            (r"(?i)\bpay\s+(now|immediately|today|within\s+\d+\s+(hours?|minutes?))\s*(or|else|otherwise)\b", 18, "Pay now or else"),
            (r"(?i)\b(morphed?|edited|fake|obscene)\s+(photos?|images?|videos?|screenshots?)\b", 30, "Morphed photo threat"),
            (r"(?i)\bblacklist\w*\s+(your\s+)?(name|cibil|credit\s+score)\b", 18, "CIBIL blacklist threat"),
        ],
    },

    "olx_quickr_scam": {
        "label": "OLX / Classifieds Scam",
        "description": (
            "Fake buyer/seller scams on OLX and Quickr — typically using fake army/defence "
            "personnel angle to build trust, then demand advance payment."
        ),
        "severity": "medium",
        "patterns": [
            (r"(?i)\b(army\s+(officer|person|colonel|major)|defence\s+personnel|military\s+officer|navy\s+officer|air\s+force\s+officer|BSF|CRPF|CISF|paramilitary)\b", 22, "Army/defence claim"),
            (r"(?i)\b(transfer\w*|post\w*|relocation|reloc\w*|posting)\b.{0,40}\b(sell\w+\s+urgently|urgent\s+sale|selling)\b", 20, "Transfer selling urgency"),
            (r"(?i)\b(advance|token)\s+(payment|amount|money)\s+(via|through|on|using)\s+(UPI|Google\s+Pay|PhonePe|Paytm|NEFT|IMPS)\b", 25, "Advance payment request"),
            (r"(?i)\bolx\.in|quikr\.com|OLX|Quickr\b", 10, "OLX/Quickr mention"),
            (r"(?i)\b(sell|selling)\s+(urgently|immediately|due\s+to\s+(transfer|posting|relocation))\b", 18, "Urgent sale"),
            (r"(?i)\b(product|item|bike|car|phone|laptop|TV|furniture)\s+(available\s+for\s+sale\s+at|for\s+sale)\s+(very\s+)?(low\s+price|half\s+price|below\s+MRP|best\s+price)\b", 16, "Too-cheap listing"),
            (r"(?i)\b(I\s+am\s+)?(buyer|seller)\s+(from|in|at)\s+(army|defence|military|BSF|CRPF|CISF|Government|GOI)\b", 20, "Govt/army buyer claim"),
            (r"(?i)\bI\s+(cannot|can.t|won.t)\s+(meet|come|visit|receive)\b.{0,40}\b(send|courier|ship|dispatch)\b", 16, "Can't meet — ship"),
            (r"(?i)\b(Google\s+Pay|PhonePe|Paytm)\s+(rs\.?|₹)?\s*[\d,]+\s+(advance|token|deposit|booking)\b", 22, "Advance via payment app"),
        ],
    },

    "investment_scam": {
        "label": "Fake Investment / Trading Scam",
        "description": (
            "Fraudulent investment schemes — Telegram trading groups, crypto scams, "
            "task-based earning, and guaranteed high-return stock tips."
        ),
        "severity": "high",
        "patterns": [
            (r"(?i)\b(guaranteed|assured|100%\s+safe)\s+(returns?|profit|income|earnings?)\b", 28, "Guaranteed returns"),
            (r"(?i)\b(double|triple|2x|3x|5x|10x|20x)\s+(your\s+)?(money|investment|profit|income)\b", 25, "Double/triple money"),
            (r"(?i)\bjoin\s+(our\s+)?(Telegram|WhatsApp)\s+(group|channel)\s+(for|to\s+get)\s+(trading|stock|crypto|investment|earning)\b", 25, "Join trading group"),
            (r"(?i)\b(crypto|bitcoin|USDT|ethereum|forex|Fx|stock|share\s+market)\s+(investment|trading)\s+(opportunity|plan|scheme|tips?)\b", 20, "Crypto/forex investment"),
            (r"(?i)\bdaily\s+(profit|income|earning|withdrawal)\s+(of\s+)?(Rs\.?|₹)?\s*[\d,]+\b", 22, "Daily profit claim"),
            (r"(?i)\bSEBI\s+registered\s+(advisor|broker|scheme|company|firm)\b", 18, "Fake SEBI registration"),
            (r"(?i)\b(IPO|stock|share)\s+(allotment|tips?|signals?)\s+(guaranteed|assured|promised|100%)\b", 22, "Guaranteed IPO tips"),
            (r"(?i)\btask\s+(based|completion)\s+(earning|income|job|work)\s+(Rs\.?|₹)?\s*[\d,]+\s+(per\s+(day|task|hour|week))?\b", 20, "Task-based earning"),
            (r"(?i)\b(part.?time\s+(job|work|income)|work\s+from\s+home)\b.{0,40}(Rs\.?|₹)?\s*[\d,]+\s+per\s+(day|hour)\b", 18, "Work from home daily income"),
            (r"(?i)\b(refer\s+and\s+earn|referral\s+bonus)\s+(Rs\.?|₹)?\s*[\d,]+\b", 15, "Referral earning"),
            (r"(?i)\binvest\s+(just|only|merely)\s+(Rs\.?|₹)?\s*[\d,]+\s+(and\s+earn|to\s+earn|for)\s+(Rs\.?|₹)?\s*[\d,]+\b", 25, "Small invest big earn"),
        ],
    },

    "otp_phishing": {
        "label": "OTP / Credential Phishing",
        "description": (
            "Extraction of OTP, PIN, ATM card details, or net banking credentials "
            "— the most common vector in Indian online banking fraud."
        ),
        "severity": "critical",
        "patterns": [
            (r"(?i)\b(share|tell|give|send|forward|read\s+out|dictate)\s+(me|us|the)\s+(OTP|one-?time\s+(password|code))\b", 35, "OTP sharing request"),
            (r"(?i)\bOTP\s+(has\s+been\s+)?(received|arrived|sent|come)\s+(on|to)\s+(your|the)\s+(phone|mobile|number|device)\b", 25, "OTP received notice"),
            (r"(?i)\bdo\s+not\s+share\s+(OTP|PIN|password)\s+(with\s+anyone)\b.{0,100}\b(but|except|only)\s+(share|tell|give|send)\s+(me|us)\b", 30, "Classic OTP social engineering"),
            (r"(?i)\b(net\s*banking|internet\s+banking|online\s+banking)\s+(user\s*(id|name)|password|login\s+credentials?)\b", 25, "Net banking credentials"),
            (r"(?i)\b(ATM|debit|credit)\s+card\s+(number|CVV|expiry|expiration|PIN|details?)\b", 25, "Card details request"),
            (r"(?i)\benter\s+(your\s+)?(ATM|card|UPI)\s+PIN\b.{0,40}\b(on\s+(phone|call|WhatsApp|this\s+link)|to\s+(receive|verify))\b", 30, "PIN entry on call"),
            (r"(?i)\b(internet\s+banking|netbanking)\s+(credentials?|login|username|password)\s+(re-?set|update|verify|provide)\b", 22, "Banking credentials reset"),
            (r"(?i)\bM-?PIN\b.{0,30}\b(share|tell|give|enter|provide)\b", 25, "MPIN request"),
            (r"(?i)\b6\s*digit\s+(OTP|code|PIN)\b", 18, "6-digit OTP"),
            (r"(?i)\b4\s*digit\s+(PIN|ATM\s+PIN)\b", 18, "4-digit ATM PIN"),
        ],
    },

    "fear_authority": {
        "label": "Fear & Authority Manipulation",
        "description": (
            "Psychological manipulation using fear of arrest, court notices, "
            "or authority impersonation to coerce immediate compliance."
        ),
        "severity": "medium",
        "patterns": [
            (r"(?i)\b(court|police|CBI|ED|Income\s+Tax|TRAI)\s+(notice|summons|warrant|raid|letter)\b", 22, "Court/police notice"),
            (r"(?i)\b(arrest|jail|prison|imprisonment|custody)\b.{0,40}\b(if\s+you|you\s+will|unless|otherwise)\b", 22, "Arrest if not compliant"),
            (r"(?i)\bFIR\s+(has\s+been\s+)?(registered|filed|lodged)\s+(against\s+you|in\s+your\s+name)\b", 22, "FIR registered against you"),
            (r"(?i)\blegal\s+(action|proceedings?|notice)\s+(will\s+be\s+)?(initiated|taken|filed|issued)\b", 18, "Legal action"),
            (r"(?i)\b(last|final)\s+(warning|notice|chance|opportunity|reminder)\b", 16, "Final warning"),
            (r"(?i)\b(seize|confiscate|freeze|attach)\s+(your\s+)?(assets|accounts?|property|funds|savings|investments)\b", 20, "Asset seizure threat"),
            (r"(?i)\b(government|official|government-?approved|certified)\s+(agency|authority|department|body)\b", 12, "Government authority claim"),
            (r"(?i)\byour\s+name\s+(is\s+)?(involved|appear\w+|found|listed)\s+(in|as)\s+(money\s+laundering|drug|fraud|criminal)\b", 22, "Name in crime"),
        ],
    },

    "urgency_pressure": {
        "label": "Urgency / Time Pressure",
        "description": (
            "Artificial urgency to prevent victim from consulting family or verifying claims "
            "before taking irreversible action."
        ),
        "severity": "low",
        "patterns": [
            (r"(?i)\bwithin\s+(30|15|10|5)\s+minutes?\b", 16, "30-min deadline"),
            (r"(?i)\bwithin\s+(24|48|12|6)\s+hours?\b", 12, "Hour deadline"),
            (r"(?i)\b(immediately|urgently|right\s+now|as\s+soon\s+as\s+possible|ASAP)\b", 10, "Immediately"),
            (r"(?i)\b(today\s+only|last\s+day|offer\s+expires|deadline\s+today)\b", 14, "Today only"),
            (r"(?i)\b(account|number|card|service)\s+will\s+(be\s+)?(suspend\w+|block\w+|deactivat\w+|closed)\s+(in|within|after)\s+\d+\b", 20, "Account closure countdown"),
            (r"(?i)\b(act|respond|reply)\s+now\s+(or|else|otherwise)\b", 16, "Act now or else"),
            (r"(?i)\bdon.?t\s+(delay|wait|ignore|neglect)\b", 12, "Don't delay"),
        ],
    },

    "fake_job_task_scam": {
        "label": "Fake Job / Task-Based Scam",
        "description": (
            "Work-from-home or task-completion scams that lure victims with small initial "
            "payments then trap them into paying larger 'fees' or 'deposits'."
        ),
        "severity": "high",
        "patterns": [
            (r"(?i)\b(work\s+from\s+home|WFH|home-?based\s+job)\b.{0,60}(Rs\.?|₹)\s*[\d,]+\b", 20, "WFH income promise"),
            (r"(?i)\bcomplete\s+(simple|easy|small)?\s*tasks?\s+(online|on\s+(WhatsApp|Telegram|app))\b.{0,50}earn\b", 22, "Simple tasks + earn"),
            (r"(?i)\b(paid\s+in\s+advance|advance\s+salary|prepaid)\b.{0,40}(job|work|task)\b", 20, "Advance pay lure"),
            (r"(?i)\b(YouTube|Instagram|Google)\s+(like|subscribe|follow|review|rating)\s+(task|job|earn)\b", 22, "Social media task scam"),
            (r"(?i)\bdeposit\s+(Rs\.?|₹)\s*[\d,]+\s+(to\s+(start|activate|unlock|begin)|as\s+(registration|security|refundable))\b", 28, "Deposit to start"),
            (r"(?i)\bregistration\s+fee\s+(Rs\.?|₹)\s*[\d,]+\b", 20, "Registration fee"),
            (r"(?i)\b(upgrade|premium|vip)\s+membership\s+(Rs\.?|₹)\s*[\d,]+\b.{0,40}earn\b", 22, "Premium membership to earn"),
            (r"(?i)\bTelegram\s+(channel|group|bot)\b.{0,40}(earn|income|profit|job|task)\b", 20, "Telegram earn group"),
        ],
    },

}

# Category display order
CATEGORY_ORDER = [
    "digital_arrest_scam",
    "otp_phishing",
    "upi_fraud",
    "whatsapp_apk_scam",
    "kyc_expiry_fraud",
    "loan_app_harassment",
    "olx_quickr_scam",
    "sim_swap_fraud",
    "investment_scam",
    "fake_job_task_scam",
    "fear_authority",
    "urgency_pressure",
]

SEVERITY_SCORES = {"critical": 5, "high": 3, "medium": 2, "low": 1}


# ---------------------------------------------------------------------------
# Analyzer Engine
# ---------------------------------------------------------------------------

def analyze_for_indian_scam(text: str, subject: str = "") -> dict:
    """
    Run comprehensive Indian scam pattern detection on the given text/subject.
    Returns per-category matches, overall risk score, and risk level.
    """
    combined = f"{subject}\n{text}".strip()

    categories: Dict[str, dict] = {}
    total_weighted_score = 0

    for cat_key, cat_def in SCAM_PATTERNS.items():
        cat_score = 0
        matched_evidence: List[str] = []

        for tup in cat_def["patterns"]:
            pattern, weight, label = tup
            hits = re.findall(pattern, combined)
            if hits:
                cat_score += weight
                matched_hit = hits[0] if isinstance(hits[0], str) else hits[0][0]
                matched_evidence.append(f"{label}: \"{matched_hit[:60]}\"")

        matched = cat_score > 0
        categories[cat_key] = {
            "label": cat_def["label"],
            "description": cat_def["description"],
            "severity": cat_def["severity"],
            "score": min(cat_score, 100),
            "matched": matched,
            "matches": matched_evidence,
        }

        if matched:
            sev_mult = SEVERITY_SCORES.get(cat_def["severity"], 1)
            total_weighted_score += min(cat_score, 100) * sev_mult

    # Normalise to 0–100
    max_possible = sum(100 * SEVERITY_SCORES[d["severity"]] for d in SCAM_PATTERNS.values())
    overall = min(int((total_weighted_score / max_possible) * 100), 100) if max_possible > 0 else 0

    # Hard-floor: if a critical category matched, score must be at least 65
    critical_hit = any(
        categories[k]["matched"] and SCAM_PATTERNS[k]["severity"] == "critical"
        for k in SCAM_PATTERNS
    )
    if critical_hit and overall < 65:
        overall = 65

    if overall >= 75:
        risk_level = "Critical"
    elif overall >= 50:
        risk_level = "High"
    elif overall >= 25:
        risk_level = "Medium"
    elif overall > 0:
        risk_level = "Low"
    else:
        risk_level = "Clean"

    detected = [k for k in CATEGORY_ORDER if categories.get(k, {}).get("matched")]

    return {
        "overall_risk_score": overall,
        "risk_level": risk_level,
        "categories": categories,
        "detected_categories": detected,
        "total_detected": len(detected),
        "critical_count": sum(
            1 for k in detected if SCAM_PATTERNS.get(k, {}).get("severity") == "critical"
        ),
        "text_length": len(text),
        "subject": subject,
    }
