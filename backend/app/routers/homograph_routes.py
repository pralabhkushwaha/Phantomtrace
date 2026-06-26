"""Homograph & domain impersonation API routes."""

import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Investigation
from ..core.analyzer import quick_domain_analysis
from ..core.homograph import analyze_domain

router = APIRouter(prefix="/api/homograph", tags=["Homograph Detection"])


class DomainRequest(BaseModel):
    domain: str


class BulkDomainRequest(BaseModel):
    domains: list[str]


@router.post("/analyze")
def analyze_single(req: DomainRequest, db: Session = Depends(get_db)):
    if not req.domain.strip():
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")
    try:
        result = quick_domain_analysis(req.domain.strip())
        inv = Investigation(
            investigation_type="domain",
            input_summary=req.domain.strip()[:200],
            risk_score=result["risk"]["total_score"],
            risk_level=result["risk"]["risk_level"],
            result_json=json.dumps(result, default=str),
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)
        result["investigation_id"] = inv.id
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/bulk")
def analyze_bulk(req: BulkDomainRequest):
    """Analyze up to 20 domains at once (no DB persist for bulk checks)."""
    if len(req.domains) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 domains per bulk request.")
    results = []
    for domain in req.domains:
        try:
            results.append(analyze_domain(domain.strip()))
        except Exception as e:
            results.append({"domain": domain, "error": str(e)})
    return {"results": results}
