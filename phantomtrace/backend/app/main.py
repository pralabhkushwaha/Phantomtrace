"""
PhantomTrace — FastAPI main application entry point.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .database import init_db
from .routers.email_forensics import router as email_router
from .routers.homograph_routes import router as homograph_router
from .routers.other_routes import url_router, content_router, history_router

app = FastAPI(
    title="PhantomTrace",
    description="Professional Phishing Detection & Email Forensics Platform",
    version="1.0.0",
)

# ── CORS ────────────────────────────────────────────────────────────────────
# In production restrict origins to your Netlify domain.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # restrict to ["https://your-site.netlify.app"] in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Database init ────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup_event():
    init_db()

# ── Routers ──────────────────────────────────────────────────────────────────
app.include_router(email_router)
app.include_router(homograph_router)
app.include_router(url_router)
app.include_router(content_router)
app.include_router(history_router)

@app.get("/")
def root():
    return {
        "app": "PhantomTrace",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs",
    }

@app.get("/health")
def health():
    return {"status": "ok"}
