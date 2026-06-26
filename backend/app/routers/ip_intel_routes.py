"""IP Intelligence — real-time geolocation, ASN, proxy & threat analysis."""

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/ip", tags=["IP Intelligence"])

FIELDS = (
    "status,message,continent,continentCode,country,countryCode,"
    "region,regionName,city,district,zip,lat,lon,timezone,currency,"
    "isp,org,as,asname,reverse,mobile,proxy,hosting,query"
)

INDIAN_ISP_KEYWORDS = [
    "jio", "reliance", "airtel", "bsnl", "vodafone", "vi ", "idea",
    "hathway", "act fibernet", "tata", "excitel", "gtpl", "spectranet",
    "sify", "YOU broadband", "atria"
]

THREAT_HOSTING_PROVIDERS = [
    "digitalocean", "linode", "vultr", "amazon", "aws", "azure",
    "google cloud", "cloudflare", "ovh", "hetzner", "contabo",
    "m247", "serverius", "leaseweb", "choopa", "akamai"
]


class IPRequest(BaseModel):
    ip: str


@router.post("/analyze")
async def analyze_ip(req: IPRequest):
    ip = req.ip.strip()
    if not ip:
        raise HTTPException(status_code=400, detail="IP address cannot be empty.")

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": FIELDS}
            )
            data = resp.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"IP lookup failed: {str(e)}")

    if data.get("status") == "fail":
        raise HTTPException(status_code=400, detail=data.get("message", "Invalid IP address."))

    # Risk scoring
    risk_score = 0
    risk_flags = []

    if data.get("proxy"):
        risk_score += 40
        risk_flags.append("Proxy / VPN detected")

    if data.get("hosting"):
        risk_score += 30
        risk_flags.append("Hosting / datacenter IP")
        isp_lower = (data.get("isp", "") + data.get("org", "")).lower()
        for provider in THREAT_HOSTING_PROVIDERS:
            if provider in isp_lower:
                risk_flags.append(f"Known cloud provider: {provider.title()}")
                break

    if data.get("mobile"):
        risk_flags.append("Mobile / cellular network")

    isp_lower = (data.get("isp", "") + data.get("org", "")).lower()
    is_indian_isp = any(kw in isp_lower for kw in INDIAN_ISP_KEYWORDS)
    if data.get("countryCode") == "IN":
        risk_flags.append("Indian IP address" + (" — Indian ISP" if is_indian_isp else ""))

    if risk_score >= 60:
        risk_level = "Critical"
    elif risk_score >= 40:
        risk_level = "High"
    elif risk_score >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "ip": data.get("query", ip),
        "geolocation": {
            "continent": data.get("continent"),
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "district": data.get("district"),
            "zip": data.get("zip"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "timezone": data.get("timezone"),
            "currency": data.get("currency"),
        },
        "network": {
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "asn_name": data.get("asname"),
            "reverse_dns": data.get("reverse"),
            "is_mobile": data.get("mobile", False),
            "is_proxy": data.get("proxy", False),
            "is_hosting": data.get("hosting", False),
            "is_indian_isp": is_indian_isp,
        },
        "risk": {
            "score": risk_score,
            "level": risk_level,
            "flags": risk_flags,
        },
    }
