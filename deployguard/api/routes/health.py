"""Health check endpoint."""

import time
from fastapi import APIRouter

from deployguard.api.schemas import HealthResponse

router = APIRouter()

# Track startup time
_startup_time = time.time()


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """
    Health check endpoint.
    
    Returns the service health status, version, and basic statistics.
    """
    from deployguard.core.scanner import SecretScanner
    
    try:
        scanner = SecretScanner()
        patterns_count = len(scanner.patterns)
    except Exception:
        patterns_count = 0
    
    return HealthResponse(
        status="healthy",
        version="0.1.6",
        patterns_loaded=patterns_count,
        uptime_seconds=time.time() - _startup_time
    )


@router.get("/ready")
async def readiness_check() -> dict:
    """
    Readiness check for Kubernetes.
    
    Returns 200 if the service is ready to accept traffic.
    """
    return {"ready": True}


@router.get("/live")
async def liveness_check() -> dict:
    """
    Liveness check for Kubernetes.
    
    Returns 200 if the service is alive.
    """
    return {"alive": True}
