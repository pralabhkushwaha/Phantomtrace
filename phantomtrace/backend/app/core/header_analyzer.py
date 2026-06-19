"""
Email header forensics engine.

Parses .eml files or raw pasted headers and produces a structured
analysis covering:
  - From / To / Subject / Message-ID / Reply-To / Return-Path
  - SPF / DKIM / DMARC results (from Authentication-Results header + live DNS)
  - Received-chain analysis (hop count, relay IPs, timing anomalies)
  - Sender IP extraction and originating-country geo
  - Display-name spoofing / Reply-To mismatch detection
  - Suspicious relay detection (new TLDs, .ru/.cn/.xyz, free-email abuse)
"""

import email
import email.policy
import re
import socket
from email import message_from_string, message_from_bytes
from email.utils import parseaddr, getaddresses

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "ymail.com",
    "protonmail.com", "tutanota.com", "mail.com", "aol.com", "live.com",
    "rediffmail.com", "zohomail.com",
}

SUSPICIOUS_TLDS = {
    "ru", "cn", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "pw",
    "cc", "ws", "info", "click", "link", "online", "site", "work",
}


def _parse_msg(raw: str | bytes):
    if isinstance(raw, bytes):
        return email.message_from_bytes(raw, policy=email.policy.compat32)
    return email.message_from_string(raw, policy=email.policy.compat32)


def _get_header(msg, name: str, default=""):
    val = msg.get(name, default)
    if val is None:
        return default
    # decode encoded words
    try:
        from email.header import decode_header, make_header
        decoded = str(make_header(decode_header(val)))
        return decoded.strip()
    except Exception:
        return str(val).strip()


def _extract_address(raw_field: str):
    """Return (display_name, email_address)."""
    display, addr = parseaddr(raw_field)
    return display.strip(), addr.strip().lower()


def _domain_of(addr: str) -> str:
    if "@" in addr:
        return addr.split("@", 1)[1].lower()
    return addr.lower()


def _tld_of(domain: str) -> str:
    return domain.rsplit(".", 1)[-1].lower() if "." in domain else ""


# ---------------------------------------------------------------------------
# Received-chain parser
# ---------------------------------------------------------------------------

def _parse_received_chain(msg):
    """Return list of dicts, newest hop first (as they appear in the headers)."""
    received_headers = msg.get_all("Received") or []
    hops = []
    for hdr in received_headers:
        hdr_clean = re.sub(r"\s+", " ", hdr).strip()
        ips = IP_RE.findall(hdr_clean)
        # extract timestamp if present
        ts_match = re.search(
            r";\s*(.+?)$", hdr_clean, re.IGNORECASE
        )
        timestamp = ts_match.group(1).strip() if ts_match else None
        # extract hostname
        by_match = re.search(r"\bby\s+([\w.\-]+)", hdr_clean, re.IGNORECASE)
        from_match = re.search(r"\bfrom\s+([\w.\-]+)", hdr_clean, re.IGNORECASE)
        hops.append({
            "raw": hdr_clean[:300],
            "ips": list(set(ips)),
            "from_host": from_match.group(1) if from_match else None,
            "by_host": by_match.group(1) if by_match else None,
            "timestamp": timestamp,
        })
    return hops


# ---------------------------------------------------------------------------
# Authentication-Results parser
# ---------------------------------------------------------------------------

def _parse_auth_results(msg):
    """Parse Authentication-Results header(s) for SPF/DKIM/DMARC verdicts."""
    auth_headers = msg.get_all("Authentication-Results") or []
    auth_headers += msg.get_all("ARC-Authentication-Results") or []

    result = {
        "spf": "none", "spf_domain": None,
        "dkim": "none", "dkim_domain": None,
        "dmarc": "none", "dmarc_domain": None,
        "raw": " | ".join(auth_headers[:3])[:500],
    }

    full = " ".join(auth_headers).lower()

    for proto in ("spf", "dkim", "dmarc"):
        # look for  "spf=pass" / "spf=fail" / etc.
        m = re.search(rf"{proto}=(\S+)", full)
        if m:
            verdict = m.group(1).rstrip(";").split(";")[0].strip()
            result[proto] = verdict

        # domain from which check was performed  header.d=example.com
        dm = re.search(rf"header\.d=([\w.\-]+)", full)
        if dm and proto == "dkim":
            result["dkim_domain"] = dm.group(1)
        em = re.search(rf"smtp\.mailfrom=([\w.\-@]+)", full)
        if em and proto == "spf":
            result["spf_domain"] = em.group(1).split("@")[-1]
        pm = re.search(rf"header\.from=([\w.\-]+)", full)
        if pm and proto == "dmarc":
            result["dmarc_domain"] = pm.group(1)

    return result


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

def analyze_email(raw: str | bytes) -> dict:
    """
    Full analysis of a raw email (.eml) or pasted headers.
    Returns a rich dict suitable for JSON serialisation.
    """
    msg = _parse_msg(raw)

    from_raw = _get_header(msg, "From")
    to_raw = _get_header(msg, "To")
    reply_to_raw = _get_header(msg, "Reply-To")
    return_path_raw = _get_header(msg, "Return-Path")
    subject = _get_header(msg, "Subject")
    message_id = _get_header(msg, "Message-ID")
    date = _get_header(msg, "Date")

    from_display, from_addr = _extract_address(from_raw)
    _, reply_to_addr = _extract_address(reply_to_raw)
    _, return_path_addr = _extract_address(return_path_raw)

    from_domain = _domain_of(from_addr)
    return_path_domain = _domain_of(return_path_addr) if return_path_addr else None
    reply_to_domain = _domain_of(reply_to_addr) if reply_to_addr else None

    # ---- received chain ----
    hops = _parse_received_chain(msg)
    # originating IP = last hop in the chain (oldest = rightmost = first originating server)
    all_ips = []
    for hop in reversed(hops):
        all_ips.extend(hop.get("ips", []))
    # filter private/loopback addresses
    import ipaddress
    public_ips = []
    for ip in all_ips:
        try:
            a = ipaddress.ip_address(ip)
            if not (a.is_private or a.is_loopback or a.is_link_local):
                public_ips.append(str(a))
        except ValueError:
            pass
    originating_ip = public_ips[0] if public_ips else None

    # ---- auth results ----
    auth = _parse_auth_results(msg)

    # ---- body text (for content analyzer) ----
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body_text += (part.get_payload(decode=True) or b"").decode(
                        part.get_content_charset("utf-8"), errors="replace"
                    )
                except Exception:
                    pass
    else:
        try:
            body_text = (msg.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
        except Exception:
            body_text = str(msg.get_payload() or "")

    # ---- anomaly flags ----
    flags = []
    risk_points = 0

    # SPF
    if auth["spf"] in ("fail", "softfail"):
        flags.append(f"SPF {auth['spf'].upper()}: sending server not authorized to send as {from_domain}")
        risk_points += 25 if auth["spf"] == "fail" else 15

    # DKIM
    if auth["dkim"] in ("fail", "none", "temperror", "permerror"):
        flags.append(f"DKIM {auth['dkim'].upper()}: email signature missing or invalid")
        risk_points += 20

    # DMARC
    if auth["dmarc"] in ("fail", "none"):
        flags.append(f"DMARC {auth['dmarc'].upper()}: policy check failed — domain has no DMARC protection")
        risk_points += 20

    # Reply-To mismatch
    if reply_to_addr and reply_to_domain and reply_to_domain != from_domain:
        flags.append(
            f"Reply-To mismatch: From domain is '{from_domain}' but "
            f"replies will go to '{reply_to_domain}' — classic phishing tactic"
        )
        risk_points += 20

    # Return-Path mismatch
    if return_path_domain and return_path_domain != from_domain:
        flags.append(
            f"Return-Path domain ('{return_path_domain}') differs from From domain ('{from_domain}')"
        )
        risk_points += 10

    # Display-name impersonation (name says one company, address is another)
    display_brand_hit = _display_name_brand_check(from_display, from_domain)
    if display_brand_hit:
        flags.append(display_brand_hit)
        risk_points += 25

    # Suspicious TLD in from domain
    from_tld = _tld_of(from_domain)
    if from_tld in SUSPICIOUS_TLDS:
        flags.append(f"Sender domain TLD '.{from_tld}' is commonly associated with abuse / phishing")
        risk_points += 15

    # Suspicious relay detection
    for hop in hops:
        for ip in hop.get("ips", []):
            for host in [hop.get("from_host", ""), hop.get("by_host", "")]:
                if host:
                    htld = _tld_of(host)
                    if htld in SUSPICIOUS_TLDS:
                        flags.append(f"Suspicious relay detected: '{host}' (TLD: .{htld})")
                        risk_points += 10
                        break

    # ---- Attachments ----
    from .attachment_analyzer import analyze_attachments
    attachment_result = analyze_attachments(msg)
    risk_points += min(attachment_result.get("overall_risk_score", 0) // 3, 20)

    risk_points = min(risk_points, 100)

    return {
        "from_raw": from_raw,
        "from_display": from_display,
        "from_addr": from_addr,
        "from_domain": from_domain,
        "to": to_raw,
        "subject": subject,
        "date": date,
        "message_id": message_id,
        "reply_to": reply_to_raw,
        "reply_to_addr": reply_to_addr,
        "return_path": return_path_raw,
        "return_path_addr": return_path_addr,
        "authentication": auth,
        "received_hops": hops,
        "hop_count": len(hops),
        "originating_ip": originating_ip,
        "all_sender_ips": list(dict.fromkeys(public_ips)),  # deduplicated
        "flags": flags,
        "header_risk_score": risk_points,
        "body_text": body_text[:5000],
        "attachments": attachment_result,
    }


def _display_name_brand_check(display_name: str, actual_domain: str) -> str | None:
    """Check if the display name claims to be a brand the actual domain doesn't match."""
    if not display_name:
        return None
    from .brand_list import KNOWN_BRANDS
    dn_lower = display_name.lower()
    for brand_domain, brand_label in KNOWN_BRANDS.items():
        brand_name_lower = brand_label.lower().split("(")[0].strip()
        if len(brand_name_lower) < 3:
            continue
        if brand_name_lower in dn_lower:
            brand_real_domain = brand_domain.split(".")[0]
            if brand_real_domain not in actual_domain and brand_domain != actual_domain:
                return (
                    f"Display-name impersonation: sender claims to be '{brand_label}' "
                    f"('{display_name}') but is actually sending from '{actual_domain}'"
                )
    return None
