# backend/main.py
from __future__ import annotations

import os
import logging
import importlib
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ---------------------- optional DB (graceful) ----------------------
try:
    from .db import engine, Base  # type: ignore
except Exception:  # pragma: no cover
    engine = None  # type: ignore
    Base = None  # type: ignore


def _include_optional_router(app: FastAPI, modname: str, tag: str, prefix: str = "/api") -> None:
    """
    Best-effort import and mount of a router module at .routes.<modname>.
    Skips cleanly (with a log) if the module or router is missing.
    """
    try:
        mod = importlib.import_module(f".routes.{modname}", package=__package__)
        router = getattr(mod, "router", None)
        if router is None:
            logging.warning(f"Router module '{modname}' has no 'router' attribute; skipping.")
            return
        app.include_router(router, prefix=prefix, tags=[tag])
        logging.info(f"Mounted router: {modname} at {prefix} (tag: {tag})")
    except Exception as e:
        logging.warning(f"Router '{modname}' not mounted ({e}).")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Optional dev-time auto-create of DB tables
    if os.getenv("DEV_CREATE_ALL") == "1":
        if Base is not None and engine is not None:
            try:
                Base.metadata.create_all(bind=engine)  # type: ignore[attr-defined]
                logging.info("DB initialized / verified (DEV_CREATE_ALL=1).")
            except Exception:
                logging.exception("DB init failed.")
        else:
            logging.info("DB not configured; skipping create_all (DEV_CREATE_ALL=1).")
    yield


# ----------------------------- app -----------------------------

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

app = FastAPI(
    title="Automated Web Vulnerability Assessment API",
    description=(
        "Proxy-based crawling, fuzzing, active scanning, and ML-driven payload recommendation."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Permissive CORS for dev; tighten before shipping to prod
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------- mount routers -------------------------
# Each is optional; absence won't crash the app.
_include_optional_router(app, "crawl_routes", "Crawl")
_include_optional_router(app, "category_routes", "Categorization")
_include_optional_router(app, "probe_routes", "Probe")
_include_optional_router(app, "recommend_routes", "Recommender")
_include_optional_router(app, "job_routes", "Job")
_include_optional_router(app, "fuzz_routes", "Fuzzing")
_include_optional_router(app, "evidence_routes", "Evidence")
_include_optional_router(app, "verify_routes", "Verify")
_include_optional_router(app, "report_routes", "Report")
_include_optional_router(app, "ml_routes", "ML")

# ------------------------- health & root -------------------------

@app.get("/")
def root():
    return {"message": "Welcome to the Automated Vulnerability Assessment API"}

@app.get("/health")
def health():
    return {"status": "ok"}
