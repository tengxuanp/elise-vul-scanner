# backend/main.py
from __future__ import annotations
import os
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ✅ Always use package-relative imports when running as backend.main
from .db import engine, Base
from .routes import (
    crawl_routes,
    category_routes,
    fuzz_routes,
    probe_routes,
    recommend_routes,
    job_routes,
    evidence_routes,
    verify_routes,
    report_routes,
    ml_routes,  # ← Stage-A/Stage-B ML endpoints
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Dev-only auto-create; remove once you care about data/migrations.
    if os.getenv("DEV_CREATE_ALL") == "1":
        try:
            Base.metadata.create_all(bind=engine)
            logging.info("DB initialized / verified (dev).")
        except Exception:
            logging.exception("DB init failed.")
            raise
    yield

app = FastAPI(
    title="Automated Web Vulnerability Assessment API",
    description="Proxy-based crawling, fuzzing, active scanning, and ML-driven payload recommendation.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: tighten before prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(crawl_routes.router, prefix="/api", tags=["Crawl"])
app.include_router(category_routes.router, prefix="/api", tags=["Categorization"])
app.include_router(probe_routes.router, prefix="/api", tags=["Probe"])
app.include_router(recommend_routes.router, prefix="/api", tags=["Recommender"])
app.include_router(job_routes.router, prefix="/api", tags=["Job"])
app.include_router(fuzz_routes.router, prefix="/api", tags=["Fuzzing"])
app.include_router(evidence_routes.router, prefix="/api", tags=["Evidence"])
app.include_router(verify_routes.router, prefix="/api", tags=["Verify"])
app.include_router(report_routes.router, prefix="/api", tags=["Report"])
app.include_router(ml_routes.router, prefix="/api", tags=["ML"])  # ← /api/ml/*

@app.get("/")
def root():
    return {"message": "Welcome to the Automated Vulnerability Assessment API"}

@app.get("/health")
def health():
    return {"status": "ok"}
