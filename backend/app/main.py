"""PhantomTrace — FastAPI main application entry point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import init_db
from .routers.email_forensics import router as email_router
from .routers.homograph_routes import router as homograph_router
from .routers.other_routes import url_router, content_router, history_router
from .routers.malware_routes import router as malware_router
from .routers.case_routes import router as case_router
from .routers.osint_routes import router as osint_router

app = FastAPI(
    title="PhantomTrace",
    description="Professional Phishing Detection, Email Forensics & Fraud Intelligence Platform",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    init_db()

app.include_router(email_router)
app.include_router(homograph_router)
app.include_router(url_router)
app.include_router(content_router)
app.include_router(history_router)
app.include_router(malware_router)
app.include_router(case_router)
app.include_router(osint_router)

@app.get("/")
def root():
    return {
        "app": "PhantomTrace",
        "version": "2.0.0",
        "status": "operational",
        "docs": "/docs",
        "modules": [
            "email_forensics", "homograph_detection", "url_intelligence",
            "content_fraud_detection", "malware_detection", "case_management",
            "phone_upi_osint"
        ]
    }

@app.get("/health")
def health():
    return {"status": "ok"}
