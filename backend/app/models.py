"""SQLAlchemy models for PhantomTrace SQLite database."""

from sqlalchemy import Column, Integer, String, Text, Float, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()


class Case(Base):
    """UP Police FIR-linked case management."""
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Case identifiers
    fir_number = Column(String(100), nullable=True, index=True)
    case_title = Column(String(300), nullable=False)
    case_type = Column(String(100), nullable=True)   # UPI Fraud, Digital Arrest, OLX Scam, etc.
    station = Column(String(200), nullable=True)     # Police Station name
    district = Column(String(100), nullable=True)
    officer_name = Column(String(200), nullable=True)
    officer_rank = Column(String(100), nullable=True)

    # Victim details
    victim_name = Column(String(200), nullable=True)
    victim_phone = Column(String(20), nullable=True)
    victim_district = Column(String(100), nullable=True)
    amount_lost = Column(Float, nullable=True)
    currency = Column(String(10), default="INR")

    # Case status
    status = Column(String(50), default="Open")   # Open, Under Investigation, Closed, Referred
    priority = Column(String(20), default="Medium")  # Low, Medium, High, Critical

    # Notes
    description = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)

    # Investigations linked to this case
    investigations = relationship("Investigation", back_populates="case")

    def __repr__(self):
        return f"<Case FIR={self.fir_number} title={self.case_title}>"


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    investigation_type = Column(String(50))
    input_summary = Column(String(500))
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(20), default="Low")
    result_json = Column(Text)

    # Optional link to a case
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)
    case = relationship("Case", back_populates="investigations")

    def __repr__(self):
        return f"<Investigation id={self.id} type={self.investigation_type} risk={self.risk_level}>"
