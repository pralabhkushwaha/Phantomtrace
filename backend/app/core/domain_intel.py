"""
Domain Intelligence Engine — UP Police Cyber Cell.

Provides:
  * WHOIS / RDAP registration data (free, no key)
  * WhoisXML API for enriched WHOIS (optional key)
  * DNS records — A, MX, NS, TXT (via DoH, no key)
  * SSL certificate info (socket, no key)
  * Domain age, registrar, risk scoring
  * Shodan domain port/service data (optional key)
"""

import os
import re
import ssl
import socket
import requests
import httpx
import asyncio
from datetime import datetime, timezone
from typing import Optional
from .dns_utils import rdap_domain_lookup, doh_query

TIMEOUT = 8


# ---------------------------------------------------------------------------
# DNS Records
# ---------------------------------------------------------------------------

def get_dns_records(domain: str) -> dict:
    """Fetch A, MX, NS, TXT records via DNS-over-HTTPS."""
    records = {}
    for rtype in ("A", "MX", "NS", "TXT"):
        answers, err = doh_query(domain, rtype)
        records[rtype] = answers if not err else []
    return records


# ---------------------------------------------------------------------------
# SSL Certificate
# ---------------------------------------------------------------------------

def get_ssl_info(domain: str) -> dict:
    """Grab SSL certificate metadata without external libraries."""
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(6)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")
        sans = [v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"]

        # Days remaining
        days_remaining = None
        try:
            exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_remaining = (exp_dt - datetime.now(timezone.utc)).days
        except Exception:
            pass

        return {
            "available": True,
            "subject": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "valid_from": not_before,
            "valid_until": not_after,
            "days_remaining": days_remaining,
            "sans": sans[:10],
            "self_signed": subject.get("commonName") == issuer.get("commonName"),
            "expired": days_remaining is not None and days_remaining < 0,
        }
    except ssl.SSLCertVerificationError:
        return {"available": True, "error": "SSL certificate verification failed (invalid/self-signed)"}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {"available": False, "error": "Could not connect to port 443"}
    except Exception as e:
        return {"available": False, "error": str(e)[:120]}


# ---------------------------------------------------------------------------
# WhoisXML API (optional key)
# ---------------------------------------------------------------------------

def get_whoisxml(domain: str) -> dict:
    api_key = os.environ.get("WHOISXML_API_KEY")
    if not api_key:
        return {"available": False}
    try:
        r = requests.get(
            "https://www.whoisxmlapi.com/whoisserver/WhoisService",
            params={
                "apiKey": api_key,
                "domainName": domain,
                "outputFormat": "JSON",
                "da": "2",
                "ip": "1",
            },
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return {"available": False, "error": f"HTTP {r.status_code}"}
        data = r.json().get("WhoisRecord", {})
        reg_info = data.get("registrant", {})
        admin_info = data.get("administrativeContact", {})

        created = data.get("createdDate", "")
        expires = data.get("expiresDate", "")
        updated = data.get("updatedDate", "")

        # Age in days
        age_days = None
        try:
            if created:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - dt).days
        except Exception:
            pass

        return {
            "available": True,
            "registrar": data.get("registrarName", ""),
            "created": created,
            "expires": expires,
            "updated": updated,
            "age_days": age_days,
            "status": data.get("status", ""),
            "registrant_name": reg_info.get("name", ""),
            "registrant_org": reg_info.get("organization", ""),
            "registrant_country": reg_info.get("country", ""),
            "registrant_email": reg_info.get("email", ""),
            "admin_email": admin_info.get("email", ""),
            "name_servers": data.get("nameServers", {}).get("hostNames", [])[:6],
            "privacy_protected": "privacy" in str(reg_info).lower() or "redacted" in str(reg_info).lower(),
            "domain_availability": data.get("domainAvailability", ""),
        }
    except Exception as e:
        return {"available": False, "error": str(e)[:120]}


# ---------------------------------------------------------------------------
# Shodan (optional key) — host lookup for domain's A record
# ---------------------------------------------------------------------------

def get_shodan_domain(domain: str) -> dict:
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return {"available": False}
    try:
        # Resolve domain to IP first
        ip = socket.gethostbyname(domain)
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return {"available": True, "ip": ip, "found": False}
        if r.status_code != 200:
            return {"available": False, "error": f"HTTP {r.status_code}"}
        data = r.json()
        ports = data.get("ports", [])
        vulns = list(data.get("vulns", {}).keys())[:10]
        hostnames = data.get("hostnames", [])
        return {
            "available": True,
            "found": True,
            "ip": ip,
            "os": data.get("os"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "open_ports": sorted(ports)[:20],
            "vulns": vulns,
            "hostnames": hostnames[:6],
            "last_update": data.get("last_update", ""),
            "tags": data.get("tags", []),
        }
    except socket.gaierror:
        return {"available": False, "error": "Domain could not be resolved"}
    except Exception as e:
        return {"available": False, "error": str(e)[:120]}


# ---------------------------------------------------------------------------
# Risk Scoring
# ---------------------------------------------------------------------------

def score_domain_risk(
    domain: str,
    rdap: dict,
    whoisxml: dict,
    ssl_info: dict,
    dns: dict,
    shodan: dict,
) -> tuple[int, list[str]]:
    score = 0
    flags = []

    # Age risk
    age = rdap.get("age_days") or whoisxml.get("age_days")
    if age is not None:
        if age < 7:
            score += 40
            flags.append(f"Domain registered only {age} day(s) ago — very new")
        elif age < 30:
            score += 30
            flags.append(f"Domain is {age} days old — recently registered")
        elif age < 90:
            score += 15
            flags.append(f"Domain is {age} days old — relatively new")

    # Suspicious TLDs
    tld = domain.rsplit(".", 1)[-1].lower()
    bad_tlds = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "pw", "cc", "work", "loan", "win", "click", "site", "online", "vip", "fun"}
    if tld in bad_tlds:
        score += 20
        flags.append(f"Suspicious TLD: .{tld}")

    # Privacy protection (can hide criminal registrants)
    if whoisxml.get("privacy_protected"):
        score += 5
        flags.append("WHOIS privacy protection enabled")

    # SSL issues
    if ssl_info.get("available") and ssl_info.get("self_signed"):
        score += 20
        flags.append("Self-signed SSL certificate — not trusted by browsers")
    if ssl_info.get("expired"):
        score += 25
        flags.append(f"SSL certificate expired ({ssl_info.get('days_remaining', '?')} days)")
    if not ssl_info.get("available") or ssl_info.get("error"):
        score += 10
        flags.append("No SSL certificate or could not connect on port 443")

    # Open high-risk ports (from Shodan)
    if shodan.get("found"):
        risky_ports = {21, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8888, 27017}
        found_risky = [p for p in shodan.get("open_ports", []) if p in risky_ports]
        if found_risky:
            score += min(len(found_risky) * 8, 25)
            flags.append(f"Open high-risk ports detected: {', '.join(map(str, found_risky))}")
        vulns = shodan.get("vulns", [])
        if vulns:
            score += min(len(vulns) * 10, 30)
            flags.append(f"CVE vulnerabilities found: {', '.join(vulns[:4])}")

    # Keyword risk in domain name
    risky_keywords = ["login", "secure", "bank", "update", "kyc", "verify", "account",
                       "sbi", "hdfc", "paytm", "income", "reward", "claim", "otp"]
    domain_lower = domain.lower()
    hit_kw = [kw for kw in risky_keywords if kw in domain_lower]
    if hit_kw:
        score += min(len(hit_kw) * 10, 25)
        flags.append(f"Suspicious keywords in domain: {', '.join(hit_kw)}")

    # No MX records (common for throwaway domains)
    if not dns.get("MX"):
        score += 5
        flags.append("No MX records — domain cannot receive email")

    score = min(score, 100)
    return score, flags


# ---------------------------------------------------------------------------
# Main analyze function
# ---------------------------------------------------------------------------

def analyze_domain(domain: str) -> dict:
    """Full domain intelligence analysis."""
    domain = domain.strip().lower().lstrip("www.")

    # Run tasks
    rdap = rdap_domain_lookup(domain)
    dns = get_dns_records(domain)
    ssl_info = get_ssl_info(domain)
    whoisxml = get_whoisxml(domain)
    shodan = get_shodan_domain(domain)

    risk_score, flags = score_domain_risk(domain, rdap, whoisxml, ssl_info, dns, shodan)

    if risk_score >= 70:
        risk_level = "Critical"
    elif risk_score >= 50:
        risk_level = "High"
    elif risk_score >= 25:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "domain": domain,
        "rdap": rdap,
        "whoisxml": whoisxml,
        "dns": dns,
        "ssl": ssl_info,
        "shodan": shodan,
        "risk": {
            "score": risk_score,
            "level": risk_level,
            "flags": flags,
        },
    }
