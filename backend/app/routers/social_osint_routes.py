"""Social Media OSINT — username presence check across major platforms."""

import httpx
import asyncio
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/social", tags=["Social OSINT"])

PLATFORMS = [
    {"name": "GitHub",       "url": "https://github.com/{u}",                    "check": "status"},
    {"name": "Reddit",       "url": "https://www.reddit.com/user/{u}/about.json", "check": "status"},
    {"name": "Twitter/X",    "url": "https://twitter.com/{u}",                   "check": "status"},
    {"name": "Instagram",    "url": "https://www.instagram.com/{u}/",             "check": "status"},
    {"name": "Telegram",     "url": "https://t.me/{u}",                           "check": "status"},
    {"name": "YouTube",      "url": "https://www.youtube.com/@{u}",               "check": "status"},
    {"name": "Pinterest",    "url": "https://www.pinterest.com/{u}/",             "check": "status"},
    {"name": "Quora",        "url": "https://www.quora.com/profile/{u}",          "check": "status"},
    {"name": "TikTok",       "url": "https://www.tiktok.com/@{u}",               "check": "status"},
    {"name": "LinkedIn",     "url": "https://www.linkedin.com/in/{u}",            "check": "status"},
    {"name": "Snapchat",     "url": "https://www.snapchat.com/add/{u}",           "check": "status"},
    {"name": "Pastebin",     "url": "https://pastebin.com/u/{u}",                 "check": "status"},
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

NOT_FOUND_CODES = {301, 302, 303, 307, 308, 404}
FOUND_CODES     = {200, 203}


async def check_platform(client: httpx.AsyncClient, platform: dict, username: str) -> dict:
    url = platform["url"].format(u=username)
    try:
        resp = await client.get(url, headers=HEADERS, follow_redirects=False, timeout=8)
        found = resp.status_code in FOUND_CODES
        return {
            "platform": platform["name"],
            "url": url,
            "found": found,
            "status_code": resp.status_code,
            "error": None,
        }
    except Exception as e:
        return {
            "platform": platform["name"],
            "url": url,
            "found": False,
            "status_code": None,
            "error": str(e)[:80],
        }


class SocialRequest(BaseModel):
    username: str


@router.post("/lookup")
async def social_lookup(req: SocialRequest):
    username = req.username.strip().lstrip("@")
    if not username:
        raise HTTPException(status_code=400, detail="Username cannot be empty.")
    if len(username) > 50:
        raise HTTPException(status_code=400, detail="Username too long.")

    async with httpx.AsyncClient() as client:
        tasks = [check_platform(client, p, username) for p in PLATFORMS]
        results = await asyncio.gather(*tasks)

    found     = [r for r in results if r["found"]]
    not_found = [r for r in results if not r["found"] and not r["error"]]
    errors    = [r for r in results if r["error"]]

    risk_score = min(len(found) * 8, 100)
    risk_level = (
        "Critical" if risk_score >= 60 else
        "High"     if risk_score >= 40 else
        "Medium"   if risk_score >= 20 else
        "Low"
    )

    return {
        "username": username,
        "summary": {
            "total_checked": len(PLATFORMS),
            "found_on": len(found),
            "not_found": len(not_found),
            "errors": len(errors),
        },
        "results": list(results),
        "found_platforms": found,
        "risk": {
            "score": risk_score,
            "level": risk_level,
            "note": f"Username '{username}' found on {len(found)} of {len(PLATFORMS)} platforms checked.",
        },
    }
