# backend/main.py
"""
Main FastAPI application for Automated Web Vulnerability Assessment API
"""
from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
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
    # Initialize browser pool
    try:
        from infrastructure.browser_pool import browser_pool
        await browser_pool.init()
        from app_state import browser_state
        browser_state.ready = True
        browser_state.error = None
        logging.info("✅ Browser pool initialized successfully")
    except Exception as e:
        from app_state import browser_state
        browser_state.ready = False
        browser_state.error = str(e)
        logging.error(f"❌ Failed to initialize browser pool: {e}")
    
    # Initialize ML engine
    try:
        from app_state import ml_state, MODEL_DIR
        from modules.ml.enhanced_inference_engine import EnhancedInferenceEngineStrict
        
        # Construct strict engine from MODEL_DIR
        ml_state.engine = EnhancedInferenceEngineStrict(MODEL_DIR)
        ml_state.ready = True
        ml_state.error = None
        logging.info("✅ ML engine initialized successfully")
    except Exception as e:
        from app_state import ml_state
        ml_state.ready = False
        ml_state.error = str(e)
        logging.error(f"❌ Failed to initialize ML engine: {e}")
    
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
    
    # Shutdown browser pool
    try:
        from infrastructure.browser_pool import browser_pool
        await browser_pool.shutdown()
        from app_state import browser_state
        browser_state.ready = False
        logging.info("✅ Browser pool shutdown complete")
    except Exception as e:
        logging.error(f"❌ Error during browser pool shutdown: {e}")

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
# Mount exactly these routers at /api as specified

# Enhanced routers (preferred over basic ones)
_include_optional_router(app, "enhanced_crawl_routes", "Capture")  # Enhanced crawl (capture-mode)
_include_optional_router(app, "crawl_routes", "Crawl")  # Legacy job-mode crawl
_include_optional_router(app, "ml_routes", "ML")  # ML routes for target granularity
_include_optional_router(app, "enhanced_fuzz_routes", "Fuzzing")  # Enhanced fuzz
_include_optional_router(app, "report_routes", "Report")  # Report routes
_include_optional_router(app, "evidence_routes", "Evidence")  # Evidence routes

# Additional optional routers
_include_optional_router(app, "category_routes", "Categorization")
_include_optional_router(app, "probe_routes", "Probe")
_include_optional_router(app, "recommend_routes", "Recommender")
_include_optional_router(app, "job_routes", "Job")
_include_optional_router(app, "verify_routes", "Verify")
_include_optional_router(app, "ml_fuzzing_routes", "ML Fuzzing")
_include_optional_router(app, "exploitation_routes", "Exploitation")

# Health endpoint
@app.get("/api/healthz")
async def health_check():
    """Health check endpoint that returns system status and mounted routers"""
    from app_state import ml_state, browser_state, MODEL_DIR, DATA_DIR
    
    # Get all mounted routes
    routers = []
    for route in app.routes:
        if hasattr(route, 'path') and route.path.startswith('/api/'):
            prefix = route.path.split('/')[2] if len(route.path.split('/')) > 2 else 'root'
            if prefix not in routers:
                routers.append(prefix)
    
    response = {
        "status": "ok",
        "routers": sorted(routers),
        "browser_ready": browser_state.ready,
        "browser_error": browser_state.error,
        "ml_ready": ml_state.ready,
        "ml_error": ml_state.error,
        "model_dir": MODEL_DIR,
        "data_dir": DATA_DIR
    }
    
    return response

# Log startup summary of mounted routes
def _log_startup_summary():
    """Log a summary of all mounted routes at startup"""
    print("\n" + "="*60)
    print("🚀 ELISE API STARTUP SUMMARY")
    print("="*60)
    
    # Get all routes from the app
    routes = []
    for route in app.routes:
        if hasattr(route, 'path') and hasattr(route, 'methods'):
            routes.append({
                'path': route.path,
                'methods': list(route.methods),
                'name': getattr(route, 'name', 'unnamed')
            })
    
    # Group routes by prefix
    route_groups = {}
    for route in routes:
        if route['path'].startswith('/api/'):
            prefix = route['path'].split('/')[2] if len(route['path'].split('/')) > 2 else 'root'
            if prefix not in route_groups:
                route_groups[prefix] = []
            route_groups[prefix].append(route)
    
    # Log grouped routes
    for group, group_routes in sorted(route_groups.items()):
        print(f"\n📁 /api/{group}/")
        for route in sorted(group_routes, key=lambda x: x['path']):
            methods_str = ', '.join(sorted(route['methods']))
            print(f"  {methods_str:15} {route['path']}")
    
    # Log health endpoint separately
    print(f"\n🏥 Health Check:")
    print(f"  GET            /api/healthz")
    
    print(f"\n✅ Total routes mounted: {len(routes)}")
    print("="*60)
    print("🎯 Enhanced routers active: crawl, fuzz")
    print("🔧 Duplicate routes eliminated")
    print("="*60 + "\n")

# Call startup summary after all routers are mounted
_log_startup_summary()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
