"""Email forensics API routes."""

import json
from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Investigation
from ..core.analyzer import full_email_analysis

router = APIRouter(prefix="/api/email", tags=["Email Forensics"])


@router.post("/analyze")
async def analyze_email_upload(
    file: UploadFile | None = File(default=None),
    raw_headers: str | None = Form(default=None),
    db: Session = Depends(get_db),
):
    """
    Accepts either:
     - An uploaded .eml file (multipart form-data, field: file)
     - Raw pasted email headers/body (form field: raw_headers)
    """
    if not file and not raw_headers:
        raise HTTPException(status_code=400, detail="Provide either an .eml file or raw email headers.")

    try:
        if file:
            raw = await file.read()
        else:
            raw = raw_headers

        result = full_email_analysis(raw)

        # Persist to DB
        inv = Investigation(
            investigation_type="email",
            input_summary=result["header"].get("from_addr", "unknown")[:200],
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
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
