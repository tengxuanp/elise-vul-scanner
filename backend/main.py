from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes import (
    crawl_routes,
    category_routes,
    fuzz_routes,
    probe_routes,
    recommend_routes,
    # exploit_routes,          # Optional if you have it
    # report_routes            # Optional if you have it
)

app = FastAPI(
    title="Automated Web Vulnerability Assessment API",
    description="Proxy-based crawling, fuzzing, active scanning, and exploitation endpoints.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Restrict this before production
    allow_methods=["*"],
    allow_headers=["*"],
)

# === API Routers Registration ===
app.include_router(crawl_routes.router, prefix="/api", tags=["Crawl"])
app.include_router(category_routes.router, prefix="/api", tags=["Categorization"])
app.include_router(probe_routes.router, prefix="/api", tags=["Probe"])
app.include_router(recommend_routes.router, prefix="/api", tags=["Recommender"])
app.include_router(fuzz_routes.router, prefix="/api", tags=["Fuzzing"])
# Optional:
# app.include_router(exploit_routes.router, prefix="/api", tags=["Exploitation"])
# app.include_router(report_routes.router, prefix="/api", tags=["Reporting"])

@app.get("/")
def root():
    return {"message": "Welcome to the Automated Vulnerability Assessment API"}
