"""Phone Number & UPI ID OSINT API routes."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from ..core.phone_upi_osint import analyze_phone_number, analyze_upi_id

router = APIRouter(prefix="/api/osint", tags=["Phone & UPI OSINT"])


class PhoneRequest(BaseModel):
    number: str


class UPIRequest(BaseModel):
    upi_id: str


@router.post("/phone")
def phone_osint(req: PhoneRequest):
    if not req.number.strip():
        raise HTTPException(status_code=400, detail="Phone number cannot be empty.")
    return analyze_phone_number(req.number.strip())


@router.post("/upi")
def upi_osint(req: UPIRequest):
    if not req.upi_id.strip():
        raise HTTPException(status_code=400, detail="UPI ID cannot be empty.")
    return analyze_upi_id(req.upi_id.strip())
