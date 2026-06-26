"""
Brand domains most frequently impersonated in phishing campaigns.
Used purely as a reference list for the homograph / typosquat detector
(core/homograph.py) -- this is standard practice in every commercial
anti-phishing engine and is required to be able to say "this domain is
likely impersonating X".

Extend this list freely -- it is plain data, no code changes required
elsewhere. Keep keys as the canonical, real domain.
"""

KNOWN_BRANDS = {
    # Big tech / global
    "google.com": "Google",
    "gmail.com": "Google (Gmail)",
    "microsoft.com": "Microsoft",
    "outlook.com": "Microsoft (Outlook)",
    "live.com": "Microsoft (Live)",
    "apple.com": "Apple",
    "icloud.com": "Apple (iCloud)",
    "amazon.com": "Amazon",
    "amazon.in": "Amazon India",
    "facebook.com": "Facebook (Meta)",
    "instagram.com": "Instagram (Meta)",
    "whatsapp.com": "WhatsApp (Meta)",
    "netflix.com": "Netflix",
    "linkedin.com": "LinkedIn",
    "twitter.com": "Twitter / X",
    "x.com": "X (Twitter)",
    "paypal.com": "PayPal",
    "dropbox.com": "Dropbox",
    "adobe.com": "Adobe",
    "yahoo.com": "Yahoo",
    "stripe.com": "Stripe",
    "visa.com": "Visa",
    "mastercard.com": "Mastercard",

    # Indian banks / fintech (very high-frequency phishing targets in India)
    "sbi.co.in": "State Bank of India",
    "onlinesbi.sbi": "State Bank of India (NetBanking)",
    "hdfcbank.com": "HDFC Bank",
    "icicibank.com": "ICICI Bank",
    "axisbank.com": "Axis Bank",
    "pnbindia.in": "Punjab National Bank",
    "bankofbaroda.in": "Bank of Baroda",
    "kotak.com": "Kotak Mahindra Bank",
    "idfcfirstbank.com": "IDFC FIRST Bank",
    "yesbank.in": "Yes Bank",
    "paytm.com": "Paytm",
    "phonepe.com": "PhonePe",
    "razorpay.com": "Razorpay",
    "bhimupi.org.in": "UPI / BHIM (NPCI)",
    "googlepay.com": "Google Pay",       # matching anchor; real product lives at pay.google.com
    "amazonpay.in": "Amazon Pay",

    # Indian government / utility (KYC, tax, ID scams)
    "uidai.gov.in": "UIDAI (Aadhaar)",
    "incometax.gov.in": "Income Tax Department India",
    "irctc.co.in": "IRCTC",
    "indiapost.gov.in": "India Post",
    "epfindia.gov.in": "EPFO",
    "digitalindia.gov.in": "Digital India",
    "uidai.in": "UIDAI (Aadhaar)",
    "digilocker.gov.in": "DigiLocker",
    "gst.gov.in": "GST Portal (India)",
    "npci.org.in": "NPCI",

    # Couriers / e-commerce (KYC / delivery scams)
    "fedex.com": "FedEx",
    "dhl.com": "DHL",
    "ups.com": "UPS",
    "flipkart.com": "Flipkart",
    "myntra.com": "Myntra",
}
