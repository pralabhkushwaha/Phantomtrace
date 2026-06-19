"""
Network helpers used by attribution.py and header_analyzer.py.

Design goal: avoid heavy/optional dependencies (dnspython, python-whois,
ipwhois) which may not be installed on every machine. Everything here is
built on top of `requests` + free, key-less, HTTPS-based services:

  * DNS resolution  -> Google / Cloudflare DNS-over-HTTPS (DoH)
  * Domain WHOIS     -> RDAP (rdap.org bootstrap, IANA-backed, no key needed)
  * IP geo / ASN / hosting provider -> ip-api.com (free tier, no key needed)

If outbound network access is unavailable (offline analysis, sandboxed
environment, firewalled machine) every function fails soft and returns a
dict with "error" set instead of raising, so the rest of the pipeline can
keep going and simply mark that field as "Unknown / Could not verify".
"""

import socket
import ipaddress
import requests

TIMEOUT = 6
HEADERS = {"User-Agent": "PhishForensicsTool/1.0"}


def _safe_get_json(url, **kwargs):
    try:
        r = requests.get(url, timeout=TIMEOUT, headers=HEADERS, **kwargs)
        if r.status_code == 200:
            return r.json(), None
        return None, f"HTTP {r.status_code}"
    except requests.exceptions.RequestException as e:
        return None, str(e)


# --------------------------------------------------------------------------
# DNS over HTTPS
# --------------------------------------------------------------------------
def doh_query(name, record_type="TXT"):
    """Query Google's DNS-over-HTTPS resolver. Returns (answers list, error)."""
    url = "https://dns.google/resolve"
    data, err = _safe_get_json(url, params={"name": name, "type": record_type})
    if err:
        # fall back to Cloudflare
        data, err2 = _safe_get_json(
            "https://cloudflare-dns.com/dns-query",
            params={"name": name, "type": record_type},
        )
        if err2:
            return [], f"DNS lookup failed: {err}"
    if not data or "Answer" not in data:
        return [], None
    answers = [a.get("data", "").strip('"') for a in data["Answer"]]
    return answers, None


def get_txt_records(domain):
    answers, err = doh_query(domain, "TXT")
    return answers, err


def get_spf_record(domain):
    answers, err = get_txt_records(domain)
    if err:
        return None, err
    for a in answers:
        if a.lower().startswith("v=spf1"):
            return a, None
    return None, None


def get_dmarc_record(domain):
    answers, err = get_txt_records(f"_dmarc.{domain}")
    if err:
        return None, err
    for a in answers:
        if a.lower().startswith("v=dmarc1"):
            return a, None
    return None, None


def get_dkim_record(domain, selector="default"):
    """DKIM selector is almost never knowable from the outside; best-effort only."""
    answers, err = get_txt_records(f"{selector}._domainkey.{domain}")
    if err:
        return None, err
    for a in answers:
        if "p=" in a.lower():
            return a, None
    return None, None


def get_mx_records(domain):
    answers, err = doh_query(domain, "MX")
    return answers, err


def reverse_dns(ip):
    """PTR lookup. Tries socket first (fast, no network restrictions issues),
    falls back to DoH PTR query."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host, None
    except (socket.herror, socket.gaierror, OSError):
        pass
    try:
        rev = ipaddress.ip_address(ip).reverse_pointer
        answers, err = doh_query(rev, "PTR")
        if answers:
            return answers[0].rstrip("."), None
        return None, err
    except ValueError as e:
        return None, str(e)


# --------------------------------------------------------------------------
# RDAP (modern replacement for WHOIS, JSON over HTTPS, no key needed)
# --------------------------------------------------------------------------
def rdap_domain_lookup(domain):
    """
    Returns dict: registrar, created, updated, age_days, status, raw
    via the open RDAP bootstrap at rdap.org (redirects to the correct
    registry RDAP server for the TLD automatically).
    """
    from datetime import datetime, timezone

    data, err = _safe_get_json(f"https://rdap.org/domain/{domain}")
    if err or not data:
        return {"error": err or "No RDAP data returned"}

    registrar = None
    created = None
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        registrar = item[3]
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            created = event.get("eventDate")

    age_days = None
    if created:
        try:
            created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created_dt).days
        except ValueError:
            pass

    return {
        "registrar": registrar or "Unknown",
        "created": created,
        "age_days": age_days,
        "status": data.get("status", []),
    }


# --------------------------------------------------------------------------
# IP geolocation / ASN / hosting provider (free, no key)
# --------------------------------------------------------------------------
def ip_geo_lookup(ip):
    """
    Returns dict: country, region, city, isp, org, asn, hosting (bool), proxy(bool)
    via ip-api.com free endpoint.
    """
    if not _is_public_ip(ip):
        return {"error": "Private/internal IP - no public attribution possible", "is_private": True}

    fields = "status,message,country,regionName,city,isp,org,as,proxy,hosting,reverse,query"
    data, err = _safe_get_json(f"http://ip-api.com/json/{ip}", params={"fields": fields})
    if err or not data:
        return {"error": err or "lookup failed"}
    if data.get("status") != "success":
        return {"error": data.get("message", "lookup failed")}

    return {
        "ip": data.get("query"),
        "country": data.get("country"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": data.get("as"),
        "is_hosting_provider": data.get("hosting", False),
        "is_proxy_or_vpn": data.get("proxy", False),
        "reverse_dns": data.get("reverse"),
    }


def _is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
    except ValueError:
        return False
