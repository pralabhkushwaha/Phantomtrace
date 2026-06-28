"""Indian Scam Scanner — dedicated high-accuracy endpoint for Indian cyber fraud."""

import json
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Investigation
from ..core.indian_scam_analyzer import analyze_for_indian_scam

router = APIRouter(prefix="/api/indian-scam", tags=["Indian Scam Scanner"])


class IndianScamRequest(BaseModel):
    text: str
    subject: str = ""


@router.post("/analyze")
def analyze_indian_scam(req: IndianScamRequest, db: Session = Depends(get_db)):
    """
    Analyze text/message content for India-specific cyber fraud patterns.
    Covers Digital Arrest, UPI Fraud, KYC Fraud, APK Scam, SIM Swap,
    Loan App Harassment, OLX Scam, Investment Scam, OTP Phishing, and more.
    """
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty.")
    if len(req.text) > 50_000:
        raise HTTPException(status_code=400, detail="Text too long (max 50 000 characters).")

    result = analyze_for_indian_scam(req.text.strip(), req.subject.strip())

    # Persist to investigation history
    try:
        inv = Investigation(
            investigation_type="indian_scam",
            input_summary=(req.subject or req.text[:80]).strip(),
            risk_score=result["overall_risk_score"],
            risk_level=result["risk_level"],
            result_json=json.dumps(result, default=str),
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)
        result["investigation_id"] = inv.id
    except Exception:
        pass  # Don't fail the response if DB write fails

    return result
