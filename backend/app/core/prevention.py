"""
Prevention & Recommendation Engine.

Generates a prioritised, context-aware checklist of recommended actions
tailored to the specific indicators found during the forensic analysis.
Always-present best-practice advice is merged with situation-specific
recommendations so the output is useful even for junior analysts.
"""

from typing import Any


def generate_recommendations(
    auth: dict = None,
    flags: list = None,
    attachment_result: dict = None,
    content_result: dict = None,
    homograph_result: dict = None,
    url_result: dict = None,
    risk_level: str = "Low",
) -> list[dict]:
    """
    Returns a list of recommendation dicts:
      { priority: "Critical|High|Medium|Low", icon: str, title: str, detail: str }
    """
    auth = auth or {}
    flags = flags or []
    attachment_result = attachment_result or {}
    content_result = content_result or {}
    homograph_result = homograph_result or {}
    url_result = url_result or {}
    recs = []

    def add(priority, icon, title, detail):
        recs.append({"priority": priority, "icon": icon, "title": title, "detail": detail})

    # ---- Authentication failures ----
    if auth.get("spf") in ("fail", "softfail"):
        add("Critical", "🛑", "Do NOT trust this email",
            "SPF check failed — the sending server is not authorised to send email on behalf of the claimed domain. This is a strong indicator of spoofing.")
    if auth.get("dkim") in ("fail", "none"):
        add("High", "⚠️", "DKIM signature is missing or invalid",
            "DKIM failure means the email's authenticity cannot be cryptographically verified. The content may have been tampered with in transit.")
    if auth.get("dmarc") in ("fail", "none"):
        add("High", "⚠️", "DMARC policy check failed",
            "The sender domain does not enforce DMARC or the email failed its DMARC check. Organisations should deploy DMARC with a 'reject' policy to prevent spoofing.")

    # ---- Spoofing flags ----
    for flag in (flags or []):
        if "reply-to mismatch" in flag.lower():
            add("Critical", "🎭", "Never reply to this email",
                "The Reply-To address is on a different domain than the From address. Any reply will go to the attacker, not the apparent sender.")
        if "display-name impersonation" in flag.lower():
            add("Critical", "🎭", "Verify sender identity through official channels",
                "The sender's display name impersonates a known brand while the actual email address is unrelated. Always check the real email address, not just the display name.")

    # ---- Attachments ----
    if attachment_result.get("has_dangerous_attachment"):
        add("Critical", "🗂️", "Do NOT open the attachment",
            "The email contains a dangerous attachment type (e.g., .exe, .apk, .vbs, .js). Opening it may install malware on your device. Report to your IT/security team immediately.")
        for att in attachment_result.get("attachments", []):
            if att.get("is_double_extension"):
                add("Critical", "🗂️", "Double-extension file detected",
                    f"'{att['filename']}' uses a double extension to disguise itself as a harmless file. Do not open or execute it.")

    # ---- APK scam ----
    if content_result.get("categories", {}).get("apk_scam", {}).get("matched"):
        add("Critical", "📱", "Never download APK files from email links",
            "No legitimate bank, government agency, or company sends APK installation files via email. These are almost exclusively used to install Android banking trojans or spyware.")

    # ---- OTP / credential theft ----
    if content_result.get("categories", {}).get("otp_request", {}).get("matched"):
        add("Critical", "🔐", "Do NOT share your OTP or verification code",
            "Legitimate companies will NEVER ask for your One-Time Password via email or phone call. Any request for an OTP is an attempt to gain access to your account.")
    if content_result.get("categories", {}).get("credential_theft", {}).get("matched"):
        add("Critical", "🔐", "Do NOT enter credentials through email links",
            "Always navigate directly to the official website instead of clicking links in email. Verify the URL carefully before entering any password or PIN.")

    # ---- Banking / KYC ----
    if content_result.get("categories", {}).get("banking_scam", {}).get("matched"):
        add("High", "🏦", "Contact your bank through official numbers only",
            "If you receive a KYC or account-block notice, call the number on the back of your bank card or visit the official website — never use contact details provided in the suspicious email.")

    # ---- Homograph / brand impersonation ----
    if homograph_result.get("likely_impersonating"):
        add("High", "🔍", f"Verify the domain — this may not be {homograph_result.get('impersonating_brand_name')}",
            f"The domain '{homograph_result.get('domain')}' visually resembles '{homograph_result.get('likely_impersonating')}' but is a different, unrelated domain. Check the address bar character by character.")

    # ---- URL signals ----
    if url_result.get("is_shortened"):
        add("High", "🔗", "Expand shortened URLs before clicking",
            "Use a URL expander (e.g., unshorten.it) to reveal the actual destination of shortened links before clicking them.")
    if url_result.get("verdict") in ("Malicious", "Suspicious"):
        add("Critical", "🔗", "Do NOT visit this URL",
            f"The URL has been flagged as '{url_result['verdict']}' by one or more threat intelligence sources. Visiting it may compromise your device or credentials.")

    # ---- Urgency / fear tactics ----
    if content_result.get("categories", {}).get("urgency", {}).get("matched") or \
       content_result.get("categories", {}).get("fear", {}).get("matched"):
        add("Medium", "⏰", "Pause before acting on urgency claims",
            "Phishing emails deliberately create artificial urgency ('act now', 'account will be suspended'). Legitimate organisations give reasonable time and do not threaten immediate consequences via email alone.")

    # ---- Universal best-practice advice (always appended) ----
    add("Medium", "🔒", "Enable Multi-Factor Authentication (MFA)",
        "Enable MFA on your email, banking, and social media accounts. Even if your password is stolen, MFA prevents unauthorised access.")
    add("Medium", "✅", "Check SPF, DKIM, and DMARC before trusting an email",
        "Use email header analysis tools to verify authentication records. Emails failing all three checks should be treated as high-risk.")
    add("Low", "🌐", "Always verify URLs before clicking",
        "Hover over links to preview the destination. Look for extra hyphens, digits replacing letters, or unusual TLDs like .xyz, .tk, or .ru.")
    add("Low", "📞", "When in doubt, verify through a different channel",
        "If an email from your bank, employer, or government seems suspicious, call the official number or visit the official website directly — do not use any contact information in the suspicious email.")
    add("Low", "🛡️", "Keep your device and antivirus software up to date",
        "Updated security software can catch known phishing URLs and malware downloads that email filtering misses.")

    return recs
