# backend/main.py
"""
Main FastAPI application for Automated Web Vulnerability Assessment API
"""
from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Add the backend directory to the Python path for imports
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Optional DB imports
try:
    from db.database import engine, Base
except ImportError:
    engine, Base = None, None

def _include_optional_router(app: FastAPI, modname: str, tag: str, prefix: str = "/api") -> None:
    """
    Include a router if it can be imported, with fallback strategies.
    
    This function attempts to import and mount routers in the following order:
    1. Absolute import from routes.{modname}
    2. Relative import from .routes.{modname} (if __package__ is set)
    3. Another absolute import from routes.{modname} (if __package__ is None)
    
    This handles the case where main.py is run directly vs. as a module.
    """
    try:
        # Strategy 1: Try absolute import first
        print(f"🔍 Attempting absolute import: routes.{modname}")
        module = __import__(f"routes.{modname}", fromlist=["router"])
        router = getattr(module, "router")
        print(f"✅ Router '{modname}' imported successfully (absolute)")
        print(f"🔍 Router routes before mounting: {[route.path for route in router.routes]}")
        print(f"🔍 Router route count before mounting: {len(router.routes)}")
        app.include_router(router, prefix=prefix, tags=[tag])
        print(f"✅ Mounted router: {modname} at {prefix} (tag: {tag})")
        print(f"🔍 Router routes after mounting: {[route.path for route in router.routes]}")
        print(f"🔍 Router route count after mounting: {len(router.routes)}")
        logging.info(f"Mounted router: {modname} at {prefix} (tag: {tag})")
    except Exception as e:
        print(f"❌ Absolute import failed for {modname}: {e}")
        try:
            # Strategy 2: Try relative import if __package__ is set
            if __package__ is not None:
                print(f"🔍 Attempting relative import: .routes.{modname}")
                module = __import__(f".routes.{modname}", fromlist=["router"], level=1)
                router = getattr(module, "router")
                print(f"✅ Router '{modname}' imported successfully (relative)")
                print(f"🔍 Router routes before mounting: {[route.path for route in router.routes]}")
                print(f"🔍 Router route count before mounting: {len(router.routes)}")
                app.include_router(router, prefix=prefix, tags=[tag])
                print(f"✅ Mounted router: {modname} at {prefix} (tag: {tag})")
                print(f"🔍 Router routes after mounting: {[route.path for route in router.routes]}")
                print(f"🔍 Router route count after mounting: {len(router.routes)}")
                logging.info(f"Mounted router: {modname} at {prefix} (tag: {tag})")
            else:
                # Strategy 3: Try another absolute import if __package__ is None
                print(f"🔍 Attempting another absolute import: routes.{modname}")
                module = __import__(f"routes.{modname}", fromlist=["router"])
                router = getattr(module, "router")
                print(f"✅ Router '{modname}' imported successfully (absolute 2)")
                print(f"🔍 Router routes before mounting: {[route.path for route in router.routes]}")
                print(f"🔍 Router route count before mounting: {len(router.routes)}")
                app.include_router(router, prefix=prefix, tags=[tag])
                print(f"✅ Mounted router: {modname} at {prefix} (tag: {tag})")
                print(f"🔍 Router routes after mounting: {[route.path for route in router.routes]}")
                print(f"🔍 Router route count after mounting: {len(router.routes)}")
                logging.info(f"Mounted router: {modname} at {prefix} (tag: {tag})")
        except Exception as e2:
            print(f"❌ Both absolute and relative imports failed for {modname}: {e2}")
            logging.warning(f"Router '{modname}' not mounted: {e2}")

def _env_true(name: str, default: bool = False) -> bool:
    v = str(os.getenv(name, "")).strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default

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

# Honor LOG_LEVEL if present; otherwise auto-enable DEBUG when ELISE_ML_DEBUG=1
_DEFAULT_LEVEL = "DEBUG" if _env_true("ELISE_ML_DEBUG", False) else "INFO"
_LOG_LEVEL = os.getenv("LOG_LEVEL", _DEFAULT_LEVEL)
logging.basicConfig(level=_LOG_LEVEL)
logging.info("Starting API (LOG_LEVEL=%s, ELISE_ML_DEBUG=%s, ELISE_ML_MODEL_DIR=%s)",
             _LOG_LEVEL, _env_true("ELISE_ML_DEBUG", False), os.getenv("ELISE_ML_MODEL_DIR") or "-")

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
_include_optional_router(app, "recommend_routes", "Recommender")  # exposes /api/recommend_payloads and /api/diagnostics/ltr
_include_optional_router(app, "job_routes", "Job")
_include_optional_router(app, "fuzz_routes", "Fuzzing")
_include_optional_router(app, "evidence_routes", "Evidence")
_include_optional_router(app, "verify_routes", "Verify")
_include_optional_router(app, "report_routes", "Report")
_include_optional_router(app, "ml_routes", "ML")

# Mount the enhanced ML fuzzer router
_include_optional_router(app, "enhanced_fuzz_routes", "Enhanced ML Fuzzing")

# Mount the enhanced crawl router
_include_optional_router(app, "enhanced_crawl_routes", "Enhanced Crawl")

# Mount the ML fuzzing router
_include_optional_router(app, "ml_fuzzing_routes", "ML Fuzzing")

# Mount the exploitation router
_include_optional_router(app, "exploitation_routes", "Exploitation")

# Note: Enhanced ML fuzzing is now handled by the enhanced_fuzz_routes router
# The direct endpoints have been removed to avoid conflicts with the new CVSS-based system

# REMOVED: Duplicate endpoint that was overriding the enhanced crawler router
# The enhanced crawler is now handled by the enhanced_crawl_routes router

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
