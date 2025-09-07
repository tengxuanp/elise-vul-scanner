from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Elise API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Mount canonical routers
from backend.routes.canonical_crawl_routes import router as crawl_router
from backend.routes.canonical_assess_routes import router as assess_router
from backend.routes.canonical_report_routes import router as report_router
from backend.routes.canonical_healthz_routes import router as health_router

app.include_router(crawl_router, prefix="/api")
app.include_router(assess_router, prefix="/api")
app.include_router(report_router, prefix="/api")
app.include_router(health_router, prefix="/api")