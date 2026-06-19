"""
Email Attribution Engine.

Given the originating sender IP (extracted by header_analyzer) and the
from-domain, builds an attribution report covering:

  - Country / Region / City of the mail server
  - Hosting provider / ISP
  - ASN (Autonomous System Number)
  - Reverse DNS (PTR record)
  - RDAP domain registration data (registrar, age, status)
  - Suspicious indicators (newly registered, bulletproof host, free-host, proxy/VPN)

All lookups are performed against free, key-less APIs via dns_utils helpers.
If the network is unavailable in the analysis environment every lookup
degrades gracefully ("Unknown / Could not verify").
"""

from .dns_utils import ip_geo_lookup, rdap_domain_lookup, reverse_dns

# Hosting providers / ASN names known for bulletproof or abuse-heavy ranges.
# This list is indicative, not exhaustive — used only to add an advisory note.
BULLETPROOF_INDICATORS = [
    "m247", "psychz", "leaseweb", "proxad", "datacamp", "shinjiru",
    "xfernet", "hostwinds", "frantech", "serverius", "sprinthost",
    "hostkey", "1984 hosting", "fozzy",
]

# Country codes most frequently seen in large-volume phishing campaigns.
# Not a block list — used only as a risk signal (with explanation).
HIGH_RISK_COUNTRY_CODES = {
    "RU": "Russia", "CN": "China", "NG": "Nigeria", "RO": "Romania",
    "UA": "Ukraine", "PK": "Pakistan", "VN": "Vietnam", "BR": "Brazil",
    "ID": "Indonesia",
}


def get_attribution(ip: str | None, domain: str | None) -> dict:
    """
    Returns a structured attribution dict.  All fields may be None / "Unknown"
    if the relevant lookup failed.
    """
    attribution = {
        "ip": ip,
        "domain": domain,
        "country": None,
        "country_code": None,
        "region": None,
        "city": None,
        "isp": None,
        "org": None,
        "asn": None,
        "is_hosting_provider": None,
        "is_proxy_or_vpn": None,
        "reverse_dns": None,
        "registrar": None,
        "domain_created": None,
        "domain_age_days": None,
        "domain_status": [],
        "risk_indicators": [],
        "attribution_confidence": "Low",  # Low | Medium | High
    }

    risk_indicators = []

    # ---- IP Geo / ASN / Hosting ----
    if ip:
        geo = ip_geo_lookup(ip)
        if "error" not in geo:
            attribution.update({
                "country": geo.get("country"),
                "country_code": None,  # ip-api returns country name, not code in free tier
                "region": geo.get("region"),
                "city": geo.get("city"),
                "isp": geo.get("isp"),
                "org": geo.get("org"),
                "asn": geo.get("asn"),
                "is_hosting_provider": geo.get("is_hosting_provider"),
                "is_proxy_or_vpn": geo.get("is_proxy_or_vpn"),
                "reverse_dns": geo.get("reverse_dns"),
            })
            attribution["attribution_confidence"] = "Medium"

            if geo.get("is_hosting_provider"):
                risk_indicators.append(
                    "Sender IP belongs to a commercial hosting provider — "
                    "legitimate corporate emails rarely originate from shared hosting"
                )
            if geo.get("is_proxy_or_vpn"):
                risk_indicators.append(
                    "Sender IP is associated with a proxy, VPN, or anonymising service"
                )

            org_lower = (geo.get("org") or "").lower()
            for bp in BULLETPROOF_INDICATORS:
                if bp in org_lower:
                    risk_indicators.append(
                        f"Sender IP ASN/org ('{geo.get('org')}') is associated with "
                        f"a provider known for abuse / bulletproof hosting"
                    )
                    break

            country = geo.get("country", "")
            for code, name in HIGH_RISK_COUNTRY_CODES.items():
                if name.lower() in country.lower():
                    risk_indicators.append(
                        f"Sender infrastructure is geolocated to {name}, a country "
                        f"frequently cited in phishing campaign reports — this is a "
                        f"risk indicator, NOT definitive attribution"
                    )
                    break

        # Reverse DNS (PTR)
        if not attribution["reverse_dns"]:
            ptr, _ = reverse_dns(ip)
            if ptr:
                attribution["reverse_dns"] = ptr

    # ---- Domain RDAP registration ----
    if domain:
        rdap = rdap_domain_lookup(domain)
        if "error" not in rdap:
            attribution["registrar"] = rdap.get("registrar")
            attribution["domain_created"] = rdap.get("created")
            attribution["domain_age_days"] = rdap.get("age_days")
            attribution["domain_status"] = rdap.get("status", [])
            attribution["attribution_confidence"] = "High" if ip else "Medium"

            age = rdap.get("age_days")
            if age is not None and age < 30:
                risk_indicators.append(
                    f"Domain was registered only {age} day(s) ago — "
                    f"newly registered domains are a strong phishing indicator"
                )
            elif age is not None and age < 90:
                risk_indicators.append(
                    f"Domain is relatively new ({age} days old) — "
                    f"consider verifying through official channels"
                )

    attribution["risk_indicators"] = risk_indicators
    return attribution
