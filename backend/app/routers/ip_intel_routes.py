"""IP Intelligence — geolocation, ASN, AbuseIPDB, AlienVault OTX, Shodan."""

import os
import httpx
import asyncio
import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/ip", tags=["IP Intelligence"])

TIMEOUT = 10

FIELDS = (
    "status,message,continent,continentCode,country,countryCode,"
    "region,regionName,city,district,zip,lat,lon,timezone,currency,"
    "isp,org,as,asname,reverse,mobile,proxy,hosting,query"
)

INDIAN_ISP_KEYWORDS = [
    "jio", "reliance", "airtel", "bsnl", "vodafone", "vi ", "idea",
    "hathway", "act fibernet", "tata", "excitel", "gtpl", "spectranet",
    "sify", "you broadband", "atria",
]

THREAT_HOSTING_PROVIDERS = [
    "digitalocean", "linode", "vultr", "amazon", "aws", "azure",
    "google cloud", "cloudflare", "ovh", "hetzner", "contabo",
    "m247", "serverius", "leaseweb", "choopa", "akamai",
]


class IPRequest(BaseModel):
    ip: str


# ── AbuseIPDB ──────────────────────────────────────────────────────────────

def _check_abuseipdb(ip: str) -> dict:
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"available": False}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return {"available": False, "error": f"HTTP {r.status_code}"}
        d = r.json().get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        total_reports = d.get("totalReports", 0)
        return {
            "available": True,
            "abuse_confidence_score": score,
            "total_reports": total_reports,
            "num_distinct_users": d.get("numDistinctUsers", 0),
            "last_reported": d.get("lastReportedAt", ""),
            "is_whitelisted": d.get("isWhitelisted", False),
            "country_code": d.get("countryCode", ""),
            "isp": d.get("isp", ""),
            "domain": d.get("domain", ""),
            "usage_type": d.get("usageType", ""),
            "verdict": (
                "Malicious" if score >= 75 else
                "Suspicious" if score >= 25 else
                "Clean"
            ),
        }
    except Exception as e:
        return {"available": False, "error": str(e)[:100]}


# ── AlienVault OTX ────────────────────────────────────────────────────────

def _check_otx(ip: str) -> dict:
    api_key = os.environ.get("OTX_API_KEY")
    if not api_key:
        return {"available": False}
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": api_key},
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return {"available": False, "error": f"HTTP {r.status_code}"}
        data = r.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])
        tags = []
        for p in pulses[:5]:
            tags.extend(p.get("tags", []))
        tags = list(set(tags))[:10]
        return {
            "available": True,
            "pulse_count": pulse_count,
            "reputation": data.get("reputation", 0),
            "tags": tags,
            "country": data.get("country_name", ""),
            "asn": data.get("asn", ""),
            "verdict": (
                "Malicious" if pulse_count >= 5 else
                "Suspicious" if pulse_count >= 1 else
                "Clean"
            ),
        }
    except Exception as e:
        return {"available": False, "error": str(e)[:100]}


# ── Shodan ────────────────────────────────────────────────────────────────

def _check_shodan(ip: str) -> dict:
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        return {"available": False}
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return {"available": True, "found": False}
        if r.status_code != 200:
            return {"available": False, "error": f"HTTP {r.status_code}"}
        data = r.json()
        ports = sorted(data.get("ports", []))[:20]
        vulns = list(data.get("vulns", {}).keys())[:8]
        # Services summary
        services = []
        for item in data.get("data", [])[:10]:
            svc = {
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
            }
            services.append(svc)
        return {
            "available": True,
            "found": True,
            "os": data.get("os"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "open_ports": ports,
            "services": services,
            "vulns": vulns,
            "hostnames": data.get("hostnames", [])[:5],
            "tags": data.get("tags", []),
            "last_update": data.get("last_update", ""),
        }
    except Exception as e:
        return {"available": False, "error": str(e)[:100]}


# ── Main route ─────────────────────────────────────────────────────────────

@router.post("/analyze")
async def analyze_ip(req: IPRequest):
    ip = req.ip.strip()
    if not ip:
        raise HTTPException(status_code=400, detail="IP address cannot be empty.")

    # Core geolocation (free, no key)
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": FIELDS},
            )
            geo_data = resp.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"IP lookup failed: {str(e)}")

    if geo_data.get("status") == "fail":
        raise HTTPException(status_code=400, detail=geo_data.get("message", "Invalid IP address."))

    # Run enrichment checks in threads (sync libs)
    loop = asyncio.get_event_loop()
    abuseipdb, otx, shodan = await asyncio.gather(
        loop.run_in_executor(None, _check_abuseipdb, ip),
        loop.run_in_executor(None, _check_otx, ip),
        loop.run_in_executor(None, _check_shodan, ip),
    )

    # Risk scoring
    risk_score = 0
    risk_flags = []

    isp_lower = (geo_data.get("isp", "") + " " + geo_data.get("org", "")).lower()
    is_indian_isp = any(kw in isp_lower for kw in INDIAN_ISP_KEYWORDS)

    if geo_data.get("proxy"):
        risk_score += 40
        risk_flags.append("Proxy / VPN detected")

    if geo_data.get("hosting"):
        risk_score += 30
        risk_flags.append("Hosting / datacenter IP")
        for provider in THREAT_HOSTING_PROVIDERS:
            if provider in isp_lower:
                risk_flags.append(f"Known cloud provider: {provider.title()}")
                break

    if geo_data.get("mobile"):
        risk_flags.append("Mobile / cellular network")

    if geo_data.get("countryCode") == "IN":
        risk_flags.append("Indian IP" + (" — Indian ISP" if is_indian_isp else ""))

    # AbuseIPDB enrichment
    if abuseipdb.get("available"):
        score = abuseipdb.get("abuse_confidence_score", 0)
        if score >= 75:
            risk_score += 40
            risk_flags.append(f"AbuseIPDB: {score}% abuse confidence ({abuseipdb.get('total_reports',0)} reports) — MALICIOUS")
        elif score >= 25:
            risk_score += 20
            risk_flags.append(f"AbuseIPDB: {score}% abuse confidence ({abuseipdb.get('total_reports',0)} reports)")

    # OTX enrichment
    if otx.get("available"):
        pc = otx.get("pulse_count", 0)
        if pc >= 5:
            risk_score += 30
            risk_flags.append(f"AlienVault OTX: IP in {pc} threat pulses — HIGH RISK")
        elif pc >= 1:
            risk_score += 15
            risk_flags.append(f"AlienVault OTX: IP in {pc} threat pulse(s)")

    # Shodan enrichment
    if shodan.get("found"):
        risky_ports = {21, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 8080, 27017}
        open_risky = [p for p in shodan.get("open_ports", []) if p in risky_ports]
        if open_risky:
            risk_score += min(len(open_risky) * 5, 20)
            risk_flags.append(f"Shodan: Open risky ports — {', '.join(map(str, open_risky))}")
        if shodan.get("vulns"):
            risk_score += min(len(shodan["vulns"]) * 8, 25)
            risk_flags.append(f"Shodan: {len(shodan['vulns'])} CVE(s) — {', '.join(shodan['vulns'][:3])}")

    risk_score = min(risk_score, 100)

    if risk_score >= 70:
        risk_level = "Critical"
    elif risk_score >= 45:
        risk_level = "High"
    elif risk_score >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Aggregate intelligence sources
    intel_sources = []
    if abuseipdb.get("available"):
        intel_sources.append({
            "source": "AbuseIPDB",
            "verdict": abuseipdb.get("verdict", "Unknown"),
            "detail": f"{abuseipdb.get('abuse_confidence_score', 0)}% confidence, {abuseipdb.get('total_reports', 0)} reports",
        })
    if otx.get("available"):
        intel_sources.append({
            "source": "AlienVault OTX",
            "verdict": otx.get("verdict", "Unknown"),
            "detail": f"{otx.get('pulse_count', 0)} threat pulse(s)",
        })
    if shodan.get("available") and shodan.get("found"):
        vulns = shodan.get("vulns", [])
        intel_sources.append({
            "source": "Shodan",
            "verdict": "Suspicious" if vulns or [p for p in shodan.get("open_ports", []) if p in {21,23,25,445,3389}] else "Info",
            "detail": f"{len(shodan.get('open_ports', []))} open port(s), {len(vulns)} CVE(s)",
        })
    if not intel_sources:
        intel_sources.append({"source": "Heuristic (add API keys for threat intel)", "verdict": risk_level, "detail": ""})

    return {
        "ip": geo_data.get("query", ip),
        "geolocation": {
            "continent": geo_data.get("continent"),
            "country": geo_data.get("country"),
            "country_code": geo_data.get("countryCode"),
            "region": geo_data.get("regionName"),
            "city": geo_data.get("city"),
            "district": geo_data.get("district"),
            "zip": geo_data.get("zip"),
            "latitude": geo_data.get("lat"),
            "longitude": geo_data.get("lon"),
            "timezone": geo_data.get("timezone"),
            "currency": geo_data.get("currency"),
        },
        "network": {
            "isp": geo_data.get("isp"),
            "org": geo_data.get("org"),
            "asn": geo_data.get("as"),
            "asn_name": geo_data.get("asname"),
            "reverse_dns": geo_data.get("reverse"),
            "is_mobile": geo_data.get("mobile", False),
            "is_proxy": geo_data.get("proxy", False),
            "is_hosting": geo_data.get("hosting", False),
            "is_indian_isp": is_indian_isp,
        },
        "threat_intel": {
            "abuseipdb": abuseipdb,
            "alienvault_otx": otx,
            "shodan": shodan,
            "sources": intel_sources,
        },
        "risk": {
            "score": risk_score,
            "level": risk_level,
            "flags": risk_flags,
        },
    }
