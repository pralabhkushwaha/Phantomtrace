"""
Social Media OSINT — Username Intelligence.
Uses official public APIs where available (GitHub, Reddit).
For other platforms: HTTP + body-content verification with honest status reporting.
"""

import httpx
import asyncio
import json
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/social", tags=["Social OSINT"])

TIMEOUT = 10

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# ---------------------------------------------------------------------------
# Platform definitions — method types:
#   "github_api"  : GitHub official API (returns JSON user object or 404)
#   "reddit_api"  : Reddit official API (returns JSON or 404)
#   "body_check"  : Fetch page body, look for found/not_found markers
#   "status_only" : Status code only (less reliable, clearly marked)
# ---------------------------------------------------------------------------

PLATFORMS = [
    {
        "name": "GitHub",
        "method": "github_api",
        "api_url": "https://api.github.com/users/{u}",
        "profile_url": "https://github.com/{u}",
        "category": "Developer",
        "reliability": "High",
    },
    {
        "name": "Reddit",
        "method": "reddit_api",
        "api_url": "https://www.reddit.com/user/{u}/about.json",
        "profile_url": "https://reddit.com/u/{u}",
        "category": "Forum",
        "reliability": "High",
    },
    {
        "name": "Telegram",
        "method": "body_check",
        "check_url": "https://t.me/{u}",
        "profile_url": "https://t.me/{u}",
        "found_markers": ["tgme_page_title", "tgme_page_description", "og:title"],
        "not_found_markers": ["tgme_page_extra", "If you have Telegram, you can contact"],
        "category": "Messaging",
        "reliability": "Medium",
    },
    {
        "name": "Instagram",
        "method": "body_check",
        "check_url": "https://www.instagram.com/{u}/",
        "profile_url": "https://www.instagram.com/{u}/",
        "found_markers": ['"username":"{u}"', 'content="@{u}'],
        "not_found_markers": ["Sorry, this page", "Page Not Found", "isn\\'t available"],
        "category": "Social",
        "reliability": "Low",
        "note": "Instagram blocks automated checks — manual verification recommended",
    },
    {
        "name": "Twitter / X",
        "method": "body_check",
        "check_url": "https://twitter.com/{u}",
        "profile_url": "https://twitter.com/{u}",
        "found_markers": ['"screen_name":"{u}"'],
        "not_found_markers": ["This account doesn", "page doesn't exist"],
        "category": "Social",
        "reliability": "Low",
        "note": "Twitter/X requires login — manual verification recommended",
    },
    {
        "name": "YouTube",
        "method": "body_check",
        "check_url": "https://www.youtube.com/@{u}",
        "profile_url": "https://www.youtube.com/@{u}",
        "found_markers": ['"channelId"', '"@{u}"', 'content="https://www.youtube.com/@{u}'],
        "not_found_markers": ["404", "This page isn't available"],
        "category": "Video",
        "reliability": "Medium",
    },
    {
        "name": "LinkedIn",
        "method": "body_check",
        "check_url": "https://www.linkedin.com/in/{u}",
        "profile_url": "https://www.linkedin.com/in/{u}",
        "found_markers": ["linkedin.com/in/{u}", '"name":'],
        "not_found_markers": ["Page not found", "This page doesn"],
        "category": "Professional",
        "reliability": "Low",
        "note": "LinkedIn blocks bots — manual verification recommended",
    },
    {
        "name": "Pinterest",
        "method": "body_check",
        "check_url": "https://www.pinterest.com/{u}/",
        "profile_url": "https://www.pinterest.com/{u}/",
        "found_markers": ['"username":"{u}"', 'content="https://www.pinterest.com/{u}'],
        "not_found_markers": ["Oops", "page not found", "404"],
        "category": "Social",
        "reliability": "Medium",
    },
    {
        "name": "TikTok",
        "method": "body_check",
        "check_url": "https://www.tiktok.com/@{u}",
        "profile_url": "https://www.tiktok.com/@{u}",
        "found_markers": ['"uniqueId":"{u}"', '"@{u}"'],
        "not_found_markers": ["Couldn't find this account", "page not found"],
        "category": "Video",
        "reliability": "Low",
        "note": "TikTok blocks most automated checks",
    },
    {
        "name": "Quora",
        "method": "body_check",
        "check_url": "https://www.quora.com/profile/{u}",
        "profile_url": "https://www.quora.com/profile/{u}",
        "found_markers": ["profile/{u}", '"name":'],
        "not_found_markers": ["Page Not Found", "doesn't exist", "404"],
        "category": "Forum",
        "reliability": "Medium",
    },
    {
        "name": "Pastebin",
        "method": "body_check",
        "check_url": "https://pastebin.com/u/{u}",
        "profile_url": "https://pastebin.com/u/{u}",
        "found_markers": [f"pastebin.com/u/{'{u}'}"],
        "not_found_markers": ["Not Found", "doesn't exist"],
        "category": "Code/Data Leak",
        "reliability": "Medium",
    },
    {
        "name": "Snapchat",
        "method": "body_check",
        "check_url": "https://www.snapchat.com/add/{u}",
        "profile_url": "https://www.snapchat.com/add/{u}",
        "found_markers": ['"username":"{u}"', "snapchat.com/add/{u}"],
        "not_found_markers": ["Page Not Found", "Sorry"],
        "category": "Messaging",
        "reliability": "Medium",
    },
]


async def check_github(client: httpx.AsyncClient, username: str, platform: dict) -> dict:
    """GitHub official API — most reliable."""
    url = platform["api_url"].format(u=username)
    try:
        resp = await client.get(
            url,
            headers={"Accept": "application/vnd.github.v3+json",
                     "User-Agent": "PhantomTrace-OSINT/2.1"},
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "platform": platform["name"],
                "found": True,
                "profile_url": platform["profile_url"].format(u=username),
                "status_code": 200,
                "reliability": platform["reliability"],
                "category": platform["category"],
                "data": {
                    "display_name": data.get("name") or username,
                    "bio": data.get("bio", ""),
                    "location": data.get("location", ""),
                    "public_repos": data.get("public_repos", 0),
                    "followers": data.get("followers", 0),
                    "following": data.get("following", 0),
                    "created_at": data.get("created_at", ""),
                    "avatar_url": data.get("avatar_url", ""),
                    "blog": data.get("blog", ""),
                    "company": data.get("company", ""),
                    "email": data.get("email", ""),
                },
                "error": None,
            }
        elif resp.status_code == 404:
            return _not_found(platform, username, 404)
        else:
            return _error(platform, username, f"HTTP {resp.status_code}")
    except Exception as e:
        return _error(platform, username, str(e)[:100])


async def check_reddit(client: httpx.AsyncClient, username: str, platform: dict) -> dict:
    """Reddit official JSON API — reliable."""
    url = platform["api_url"].format(u=username)
    try:
        resp = await client.get(
            url,
            headers={**BROWSER_HEADERS, "Accept": "application/json"},
            follow_redirects=True,
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            try:
                data = resp.json().get("data", {})
                return {
                    "platform": platform["name"],
                    "found": True,
                    "profile_url": platform["profile_url"].format(u=username),
                    "status_code": 200,
                    "reliability": platform["reliability"],
                    "category": platform["category"],
                    "data": {
                        "display_name": data.get("name", username),
                        "karma": data.get("total_karma", 0),
                        "link_karma": data.get("link_karma", 0),
                        "comment_karma": data.get("comment_karma", 0),
                        "created_utc": data.get("created_utc", 0),
                        "is_gold": data.get("is_gold", False),
                        "verified": data.get("verified", False),
                    },
                    "error": None,
                }
            except Exception:
                return _not_found(platform, username, 200)
        elif resp.status_code == 404:
            return _not_found(platform, username, 404)
        else:
            return _error(platform, username, f"HTTP {resp.status_code}")
    except Exception as e:
        return _error(platform, username, str(e)[:100])


async def check_body(client: httpx.AsyncClient, username: str, platform: dict) -> dict:
    """Body-content verification for platforms without public APIs."""
    url = platform["check_url"].format(u=username)
    found_markers = [m.format(u=username) if "{u}" in m else m
                     for m in platform.get("found_markers", [])]
    not_found_markers = platform.get("not_found_markers", [])
    try:
        resp = await client.get(
            url, headers=BROWSER_HEADERS,
            follow_redirects=True, timeout=TIMEOUT,
        )
        body = resp.text.lower()

        # Check not-found markers first
        if any(nf.lower() in body for nf in not_found_markers):
            return _not_found(platform, username, resp.status_code)

        # Check found markers
        if resp.status_code == 200:
            found_hit = any(fm.lower() in body for fm in found_markers)
            return {
                "platform": platform["name"],
                "found": found_hit,
                "profile_url": platform["profile_url"].format(u=username),
                "status_code": resp.status_code,
                "reliability": platform["reliability"],
                "category": platform["category"],
                "data": {},
                "note": platform.get("note", ""),
                "error": None if found_hit else "Profile not found or blocked",
            }

        if resp.status_code == 404:
            return _not_found(platform, username, 404)

        return _error(platform, username, f"HTTP {resp.status_code}")

    except httpx.TimeoutException:
        return _error(platform, username, "Timeout — platform may be blocking requests")
    except Exception as e:
        return _error(platform, username, str(e)[:100])


def _not_found(platform, username, code):
    return {
        "platform": platform["name"],
        "found": False,
        "profile_url": platform["profile_url"].format(u=username),
        "status_code": code,
        "reliability": platform["reliability"],
        "category": platform["category"],
        "data": {},
        "note": platform.get("note", ""),
        "error": None,
    }


def _error(platform, username, msg):
    return {
        "platform": platform["name"],
        "found": False,
        "profile_url": platform["profile_url"].format(u=username),
        "status_code": None,
        "reliability": platform["reliability"],
        "category": platform["category"],
        "data": {},
        "note": platform.get("note", f"Error: {msg}"),
        "error": msg,
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
        tasks = []
        for p in PLATFORMS:
            if p["method"] == "github_api":
                tasks.append(check_github(client, username, p))
            elif p["method"] == "reddit_api":
                tasks.append(check_reddit(client, username, p))
            else:
                tasks.append(check_body(client, username, p))

        results = await asyncio.gather(*tasks, return_exceptions=False)

    found = [r for r in results if r["found"]]
    high_rel = [r for r in found if r["reliability"] == "High"]

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
            "confirmed_found": len(high_rel),
            "not_found": len([r for r in results if not r["found"] and not r["error"]]),
            "blocked_or_error": len([r for r in results if r["error"]]),
        },
        "results": list(results),
        "found_platforms": found,
        "risk": {
            "score": risk_score,
            "level": risk_level,
            "note": f"Username '{username}' confirmed on {len(high_rel)} platform(s), possible on {len(found)} total.",
        },
        "investigation_note": (
            "GitHub and Reddit results are from official APIs — highly reliable. "
            "Instagram, Twitter, LinkedIn block automated checks — use manual verification links. "
            "For legal identity disclosure: serve legal notice to platform under IT Act Sec 67/79."
        ),
    }
