"""Domain Intelligence — WHOIS, DNS, SSL, Shodan, risk scoring."""

import json
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Investigation
from ..core.domain_intel import analyze_domain

router = APIRouter(prefix="/api/domain", tags=["Domain Intelligence"])


class DomainRequest(BaseModel):
    domain: str


@router.post("/analyze")
def domain_analyze(req: DomainRequest, db: Session = Depends(get_db)):
    """
    Full domain intelligence: WHOIS/RDAP registration, DNS records,
    SSL certificate, Shodan port/vulnerability data, and risk scoring.
    """
    domain = req.domain.strip().lower()
    # Strip protocol if user pastes a URL
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    if not domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")
    if len(domain) > 253:
        raise HTTPException(status_code=400, detail="Domain name too long.")

    result = analyze_domain(domain)

    try:
        inv = Investigation(
            investigation_type="domain_intel",
            input_summary=domain,
            risk_score=result["risk"]["score"],
            risk_level=result["risk"]["level"],
            result_json=json.dumps(result, default=str),
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)
        result["investigation_id"] = inv.id
    except Exception:
        pass

    return result
