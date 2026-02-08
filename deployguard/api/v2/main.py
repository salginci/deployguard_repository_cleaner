"""
DeployGuard API v2 - Main Application
FastAPI application with background task processing
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging

from .routes import router
from .models import init_db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info("Starting DeployGuard API v2...")
    
    # Initialize database
    database_url = os.getenv('DATABASE_URL', 'sqlite:///deployguard.db')
    init_db(database_url)
    logger.info(f"Database initialized: {database_url.split('@')[-1] if '@' in database_url else database_url}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down DeployGuard API v2...")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application"""
    
    app = FastAPI(
        title="DeployGuard API",
        description="""
## Repository Security Scanner & Cleaner API

DeployGuard helps you migrate repositories securely by:
- 🔍 **Scanning** repositories for secrets, credentials, and sensitive data
- 🧹 **Cleaning** git history to remove detected secrets
- 📦 **Pushing** cleaned repositories to new destinations

### Workflow

1. **Create a scan job** - `POST /api/v2/jobs`
2. **Wait for scan to complete** - Poll `GET /api/v2/jobs/{id}`
3. **Review found secrets** - `GET /api/v2/jobs/{id}/secrets`
4. **Select secrets to clean** - `POST /api/v2/jobs/{id}/secrets/select`
5. **Start cleaning** - `POST /api/v2/jobs/{id}/clean`
6. **Download or push** - `GET /api/v2/jobs/{id}/download` or `POST /api/v2/jobs/{id}/push`

### Authentication

All endpoints require the `X-User-ID` header (provided by your auth gateway).

### Rate Limits

- Max concurrent jobs per user: 5
- Max job retention: 7 days
- Max repository size: 5GB
        """,
        version="2.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json"
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.getenv('CORS_ORIGINS', '*').split(','),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include routers
    app.include_router(router)
    
    # Exception handlers
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"}
        )
    
    # Root endpoint
    @app.get("/")
    async def root():
        return {
            "service": "DeployGuard API",
            "version": "2.0.0",
            "docs": "/docs",
            "health": "/api/v2/health"
        }
    
    return app


# Application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "deployguard.api.v2.main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        reload=os.getenv("DEBUG", "false").lower() == "true"
    )
