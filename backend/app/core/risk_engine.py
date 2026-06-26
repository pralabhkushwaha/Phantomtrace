"""
Risk Scoring Engine.

Aggregates findings from all detection modules into a single
risk score (0-100) with a risk level label and a human-readable
explanation of every contributing factor.

Score composition (max contribution per module, hard-capped at 100):
  Header / authentication failures     up to 40 pts
  Domain attribution (age, geo, host)  up to 20 pts
  Content social-engineering           up to 25 pts
  Attachment risk                      up to 20 pts
  Homograph / brand impersonation      up to 30 pts
  URL reputation / signals             up to 30 pts
"""


def compute_risk_score(
    header_score: int = 0,
    attribution_indicators: list = None,
    content_score: int = 0,
    attachment_score: int = 0,
    homograph_confidence: int = 0,
    url_score: int = 0,
) -> dict:
    """
    Parameters are the per-module sub-scores (0-100 each).
    Returns:
      {
        total_score, risk_level,
        breakdown: {module: pts_awarded},
        explanations: [str, ...]
      }
    """
    attribution_indicators = attribution_indicators or []
    explanations = []
    breakdown = {}

    # ---- Header ----
    header_pts = min(int(header_score * 0.40), 40)
    breakdown["Email Header Forensics"] = header_pts
    if header_pts >= 25:
        explanations.append(f"Critical authentication failures detected in email headers (contributing {header_pts} pts)")
    elif header_pts >= 10:
        explanations.append(f"Email header anomalies found (contributing {header_pts} pts)")

    # ---- Attribution ----
    attr_pts = min(len(attribution_indicators) * 7, 20)
    breakdown["Sender Attribution"] = attr_pts
    if attribution_indicators:
        explanations.append(
            f"Sender infrastructure risk signals: {len(attribution_indicators)} indicator(s) detected"
        )

    # ---- Content ---- (direct 1:1 mapping, capped at 40 pts)
    content_pts = min(int(content_score * 0.40), 40)
    breakdown["Email Content Analysis"] = content_pts
    if content_pts >= 25:
        explanations.append(f"High-risk social-engineering patterns in email body (contributing {content_pts} pts)")
    elif content_pts >= 10:
        explanations.append(f"Suspicious content patterns detected (contributing {content_pts} pts)")

    # ---- Attachment ----
    attach_pts = min(int(attachment_score * 0.35), 35)
    breakdown["Attachment Analysis"] = attach_pts
    if attach_pts >= 20:
        explanations.append(f"Dangerous attachment detected (contributing {attach_pts} pts)")
    elif attach_pts > 0:
        explanations.append(f"Suspicious attachment found (contributing {attach_pts} pts)")

    # ---- Homograph ----
    hg_pts = min(int(homograph_confidence * 0.40), 40)
    breakdown["Homograph / Brand Impersonation"] = hg_pts
    if hg_pts >= 25:
        explanations.append(f"High-confidence brand impersonation via homograph attack (contributing {hg_pts} pts)")
    elif hg_pts > 0:
        explanations.append(f"Possible domain impersonation detected (contributing {hg_pts} pts)")

    # ---- URL ---- (direct mapping, capped at 40 pts)
    url_pts = min(int(url_score * 0.40), 40)
    breakdown["URL Intelligence"] = url_pts
    if url_pts >= 28:
        explanations.append(f"Malicious / high-risk URL detected (contributing {url_pts} pts)")
    elif url_pts > 0:
        explanations.append(f"Suspicious URL characteristics found (contributing {url_pts} pts)")

    total = min(
        header_pts + attr_pts + content_pts + attach_pts + hg_pts + url_pts,
        100,
    )

    if total >= 75:
        level = "Critical"
    elif total >= 50:
        level = "High"
    elif total >= 25:
        level = "Medium"
    else:
        level = "Low"

    if not explanations:
        explanations.append("No significant risk indicators detected across all modules.")

    return {
        "total_score": total,
        "risk_level": level,
        "breakdown": breakdown,
        "explanations": explanations,
    }
