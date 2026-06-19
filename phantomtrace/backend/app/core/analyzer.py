"""
PhantomTrace Analysis Orchestrator.

Single entry-point that:
  1. Parses the email (header forensics)
  2. Runs attribution on the originating IP / domain
  3. Analyzes email body content
  4. Checks homograph attacks on the from-domain and any URLs found
  5. Analyzes all URLs found in the body / headers
  6. Computes the aggregate risk score
  7. Generates prevention recommendations

Returns one big dict that the FastAPI routers can serialise directly.
"""

import re
from .header_analyzer import analyze_email
from .attribution import get_attribution
from .content_analyzer import analyze_content
from .homograph import analyze_domain
from .url_analyzer import analyze_url
from .risk_engine import compute_risk_score
from .prevention import generate_recommendations

URL_RE = re.compile(r"https?://[^\s\"'<>\]{}|\\^`]+", re.IGNORECASE)


def full_email_analysis(raw_email: str | bytes) -> dict:
    """Run every module on a raw .eml file or pasted headers+body."""

    # 1. Header analysis
    header = analyze_email(raw_email)

    # 2. Attribution
    attribution = get_attribution(
        ip=header.get("originating_ip"),
        domain=header.get("from_domain"),
    )

    # 3. Content analysis
    body = header.get("body_text", "")
    subject = header.get("subject", "")
    content = analyze_content(body, subject)

    # 4. Homograph on sender domain
    sender_domain = header.get("from_domain", "")
    homograph = analyze_domain(sender_domain) if sender_domain else {}

    # 5. URL extraction and analysis (first 5 unique URLs in body)
    urls_found = list(dict.fromkeys(URL_RE.findall(body)))[:5]
    url_analyses = []
    for url in urls_found:
        try:
            url_analyses.append(analyze_url(url, follow_redirects=False))
        except Exception as e:
            url_analyses.append({"url": url, "error": str(e), "risk_score": 0, "verdict": "Error"})

    max_url_score = max((u.get("risk_score", 0) for u in url_analyses), default=0)
    max_url_result = next((u for u in url_analyses if u.get("risk_score") == max_url_score), {})

    # 6. Risk score
    risk = compute_risk_score(
        header_score=header.get("header_risk_score", 0),
        attribution_indicators=attribution.get("risk_indicators", []),
        content_score=content.get("overall_risk_score", 0),
        attachment_score=header.get("attachments", {}).get("overall_risk_score", 0),
        homograph_confidence=homograph.get("confidence", 0),
        url_score=max_url_score,
    )

    # 7. Prevention
    recommendations = generate_recommendations(
        auth=header.get("authentication", {}),
        flags=header.get("flags", []),
        attachment_result=header.get("attachments", {}),
        content_result=content,
        homograph_result=homograph,
        url_result=max_url_result,
        risk_level=risk["risk_level"],
    )

    return {
        "header": header,
        "attribution": attribution,
        "content": content,
        "homograph_sender": homograph,
        "urls": url_analyses,
        "risk": risk,
        "recommendations": recommendations,
    }


def quick_domain_analysis(domain: str) -> dict:
    """Standalone homograph + attribution check on a single domain."""
    homograph = analyze_domain(domain)
    attribution = get_attribution(ip=None, domain=domain)
    risk = compute_risk_score(homograph_confidence=homograph.get("confidence", 0))
    recommendations = generate_recommendations(homograph_result=homograph, risk_level=risk["risk_level"])
    return {
        "domain": domain,
        "homograph": homograph,
        "attribution": attribution,
        "risk": risk,
        "recommendations": recommendations,
    }


def quick_url_analysis(url: str) -> dict:
    """Standalone URL intelligence check."""
    result = analyze_url(url, follow_redirects=True)
    domain = result.get("domain", "")
    attribution = get_attribution(ip=None, domain=domain) if domain else {}
    risk = compute_risk_score(
        url_score=result.get("risk_score", 0),
        attribution_indicators=attribution.get("risk_indicators", []),
    )
    recommendations = generate_recommendations(url_result=result, risk_level=risk["risk_level"])
    return {
        "url_analysis": result,
        "attribution": attribution,
        "risk": risk,
        "recommendations": recommendations,
    }


def quick_content_analysis(text: str, subject: str = "") -> dict:
    """Standalone email body fraud pattern detection."""
    content = analyze_content(text, subject)
    risk = compute_risk_score(content_score=content.get("overall_risk_score", 0))
    recommendations = generate_recommendations(content_result=content, risk_level=risk["risk_level"])
    return {
        "content": content,
        "risk": risk,
        "recommendations": recommendations,
    }
