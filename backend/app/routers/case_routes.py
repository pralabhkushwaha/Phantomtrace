"""Case Management API — FIR-linked case tracking for UP Police."""

import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Case, Investigation

router = APIRouter(prefix="/api/cases", tags=["Case Management"])


class CaseCreate(BaseModel):
    case_title: str
    fir_number: Optional[str] = None
    case_type: Optional[str] = None
    station: Optional[str] = None
    district: Optional[str] = None
    officer_name: Optional[str] = None
    officer_rank: Optional[str] = None
    victim_name: Optional[str] = None
    victim_phone: Optional[str] = None
    victim_district: Optional[str] = None
    amount_lost: Optional[float] = None
    description: Optional[str] = None
    priority: str = "Medium"


class CaseUpdate(BaseModel):
    case_title: Optional[str] = None
    fir_number: Optional[str] = None
    case_type: Optional[str] = None
    station: Optional[str] = None
    district: Optional[str] = None
    officer_name: Optional[str] = None
    officer_rank: Optional[str] = None
    victim_name: Optional[str] = None
    victim_phone: Optional[str] = None
    victim_district: Optional[str] = None
    amount_lost: Optional[float] = None
    description: Optional[str] = None
    notes: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None


def _case_to_dict(case: Case) -> dict:
    return {
        "id": case.id,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "fir_number": case.fir_number,
        "case_title": case.case_title,
        "case_type": case.case_type,
        "station": case.station,
        "district": case.district,
        "officer_name": case.officer_name,
        "officer_rank": case.officer_rank,
        "victim_name": case.victim_name,
        "victim_phone": case.victim_phone,
        "victim_district": case.victim_district,
        "amount_lost": case.amount_lost,
        "currency": case.currency,
        "status": case.status,
        "priority": case.priority,
        "description": case.description,
        "notes": case.notes,
        "investigation_count": len(case.investigations) if case.investigations else 0,
    }


@router.get("/")
def list_cases(status: str = None, db: Session = Depends(get_db)):
    q = db.query(Case).order_by(Case.updated_at.desc())
    if status:
        q = q.filter(Case.status == status)
    cases = q.limit(100).all()
    return [_case_to_dict(c) for c in cases]


@router.post("/")
def create_case(req: CaseCreate, db: Session = Depends(get_db)):
    case = Case(**req.model_dump())
    db.add(case)
    db.commit()
    db.refresh(case)
    return _case_to_dict(case)


@router.get("/{case_id}")
def get_case(case_id: int, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    result = _case_to_dict(case)
    # Include all linked investigations
    result["investigations"] = [
        {
            "id": inv.id,
            "type": inv.investigation_type,
            "summary": inv.input_summary,
            "risk_score": inv.risk_score,
            "risk_level": inv.risk_level,
            "created_at": inv.created_at.isoformat() if inv.created_at else None,
        }
        for inv in (case.investigations or [])
    ]
    return result


@router.patch("/{case_id}")
def update_case(case_id: int, req: CaseUpdate, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    for field, value in req.model_dump(exclude_none=True).items():
        setattr(case, field, value)
    case.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(case)
    return _case_to_dict(case)


@router.delete("/{case_id}")
def delete_case(case_id: int, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    db.delete(case)
    db.commit()
    return {"deleted": True, "id": case_id}


@router.post("/{case_id}/link/{investigation_id}")
def link_investigation(case_id: int, investigation_id: int, db: Session = Depends(get_db)):
    """Link an existing investigation to a case."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    inv.case_id = case_id
    db.commit()
    return {"linked": True, "case_id": case_id, "investigation_id": investigation_id}


@router.delete("/{case_id}/unlink/{investigation_id}")
def unlink_investigation(case_id: int, investigation_id: int, db: Session = Depends(get_db)):
    """Unlink an investigation from a case."""
    inv = db.query(Investigation).filter(
        Investigation.id == investigation_id,
        Investigation.case_id == case_id
    ).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found in this case")
    inv.case_id = None
    db.commit()
    return {"unlinked": True}
