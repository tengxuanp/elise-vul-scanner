from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes import crawl_routes, fuzz_routes, zap_routes, zap_active_routes, zap_alerts_routes, zap_combined_scan_routes  # use relative path, no 'backend.'

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Secure this later
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(crawl_routes.router, prefix="/api")
app.include_router(fuzz_routes.router, prefix="/api")
app.include_router(zap_routes.router, prefix="/api")
app.include_router(zap_active_routes.router, prefix="/api")
app.include_router(zap_alerts_routes.router, prefix="/api")
app.include_router(zap_combined_scan_routes.router, prefix="/api")
