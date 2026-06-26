"""
Phishing Email Forensics Toolkit - core package.

Modules:
    dns_utils           -> DNS-over-HTTPS, RDAP and IP-geo helpers (network)
    brand_list          -> known/high-value brand domains used for homograph matching
    header_analyzer      -> .eml / raw header parsing, SPF/DKIM/DMARC, Received chain
    attribution          -> hosting/ASN/country/registrar attribution for the sender
    homograph             -> punycode + confusable-character + typosquat detector
    content_analyzer     -> social-engineering pattern detector (urgency, OTP, APK, etc.)
    attachment_analyzer   -> dangerous extension / double-extension detector
    url_reputation        -> VirusTotal + AbuseIPDB + URLHaus + PhishTank aggregator
    risk_engine            -> combines every module's findings into one risk score
    prevention             -> generates a tailored "what to do" checklist
    report_generator        -> builds the PDF evidence report (reportlab)
    analyzer                -> orchestrates all of the above into one call
"""
