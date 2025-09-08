from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Elise API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Mount canonical routers (keeping only non-conflicting ones)
from backend.routes.canonical_report_routes import router as report_router
from backend.routes.canonical_healthz_routes import router as health_router
from backend.routes.canonical_evidence_routes import router as evidence_router

# Mount new refactored routers
from backend.routes.crawl_routes import router as new_crawl_router
from backend.routes.assess_routes import router as new_assess_router

# Use new refactored routes for crawl and assess
app.include_router(new_crawl_router, prefix="/api")
app.include_router(new_assess_router, prefix="/api")

# Keep canonical routes for other endpoints
app.include_router(report_router, prefix="/api")
app.include_router(health_router, prefix="/api")
app.include_router(evidence_router, prefix="/api")