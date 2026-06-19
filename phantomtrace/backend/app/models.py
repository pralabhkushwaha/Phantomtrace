"""SQLAlchemy models for PhantomTrace SQLite database."""

from sqlalchemy import Column, Integer, String, Text, Float, DateTime, Boolean
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    investigation_type = Column(String(50))  # email | domain | url | content
    input_summary = Column(String(500))       # from-address / domain / url snippet
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(20), default="Low")
    result_json = Column(Text)               # full JSON result blob

    def __repr__(self):
        return f"<Investigation id={self.id} type={self.investigation_type} risk={self.risk_level}>"
