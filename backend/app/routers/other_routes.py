"""URL Intelligence, Content Fraud Detection, Investigation History API routes."""

import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Investigation
from ..core.analyzer import quick_url_analysis, quick_content_analysis

# ───────────────────────────────────────────────
# URL Intelligence
# ───────────────────────────────────────────────
url_router = APIRouter(prefix="/api/url", tags=["URL Intelligence"])


class URLRequest(BaseModel):
    url: str
    follow_redirects: bool = True


@url_router.post("/analyze")
def analyze_url_endpoint(req: URLRequest, db: Session = Depends(get_db)):
    if not req.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    try:
        result = quick_url_analysis(req.url.strip())
        inv = Investigation(
            investigation_type="url",
            input_summary=req.url.strip()[:200],
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


# ───────────────────────────────────────────────
# Content / Fraud Detection
# ───────────────────────────────────────────────
content_router = APIRouter(prefix="/api/content", tags=["Fraud Detection"])


class ContentRequest(BaseModel):
    text: str
    subject: str = ""


@content_router.post("/analyze")
def analyze_content_endpoint(req: ContentRequest, db: Session = Depends(get_db)):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Email content cannot be empty.")
    try:
        result = quick_content_analysis(req.text.strip(), req.subject.strip())
        inv = Investigation(
            investigation_type="content",
            input_summary=(req.subject or req.text[:80]).strip()[:200],
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


# ───────────────────────────────────────────────
# Investigation History
# ───────────────────────────────────────────────
history_router = APIRouter(prefix="/api/history", tags=["History"])


@history_router.get("/")
def get_history(limit: int = 20, db: Session = Depends(get_db)):
    investigations = (
        db.query(Investigation)
        .order_by(Investigation.created_at.desc())
        .limit(min(limit, 100))
        .all()
    )
    return [
        {
            "id": inv.id,
            "type": inv.investigation_type,
            "summary": inv.input_summary,
            "risk_score": inv.risk_score,
            "risk_level": inv.risk_level,
            "created_at": inv.created_at.isoformat() if inv.created_at else None,
        }
        for inv in investigations
    ]


@history_router.get("/{investigation_id}")
def get_investigation(investigation_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    result = json.loads(inv.result_json)
    result["investigation_id"] = inv.id
    result["investigation_type"] = inv.investigation_type
    result["created_at"] = inv.created_at.isoformat() if inv.created_at else None
    return result


@history_router.delete("/all")
def delete_all_history(db: Session = Depends(get_db)):
    """Delete all investigation records."""
    count = db.query(Investigation).count()
    db.query(Investigation).delete()
    db.commit()
    return {"deleted": True, "count": count}


@history_router.delete("/{investigation_id}")
def delete_investigation(investigation_id: int, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    db.delete(inv)
    db.commit()
    return {"deleted": True, "id": investigation_id}
