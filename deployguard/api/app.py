"""FastAPI application factory."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from deployguard.api.routes import scan, verify, patterns, health, repos


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    
    app = FastAPI(
        title="DeployGuard API",
        description="Secret Detection & Verification API - No JWT (behind BFF)",
        version="0.1.6",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    
    # CORS - open for internal BFF usage
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Include routers
    app.include_router(health.router, tags=["Health"])
    app.include_router(scan.router, prefix="/api/v1", tags=["Scan"])
    app.include_router(verify.router, prefix="/api/v1", tags=["Verify"])
    app.include_router(patterns.router, prefix="/api/v1", tags=["Patterns"])
    app.include_router(repos.router, prefix="/api/v1", tags=["Repositories"])
    
    # Stats endpoint
    @app.get("/api/v1/stats", tags=["Stats"])
    async def get_stats():
        """Get overall statistics."""
        from deployguard.api.routes.scan import _scans
        from deployguard.core.scanner import SecretScanner
        
        scans_list = list(_scans.values())
        
        findings_by_severity = {}
        findings_by_type = {}
        pattern_counts = {}
        total_findings = 0
        
        for scan_data in scans_list:
            for finding in scan_data.get("findings", []):
                total_findings += 1
                sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
                findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1
                ftype = finding.finding_type.value if hasattr(finding.finding_type, 'value') else str(finding.finding_type)
                findings_by_type[ftype] = findings_by_type.get(ftype, 0) + 1
                pattern_counts[finding.pattern_id] = pattern_counts.get(finding.pattern_id, 0) + 1
        
        # Load patterns count
        try:
            scanner = SecretScanner()
            patterns_count = len(scanner.patterns)
        except:
            patterns_count = 0
        
        return {
            "total_scans": len(scans_list),
            "total_findings": total_findings,
            "total_patterns": patterns_count,
            "findings_by_severity": findings_by_severity,
            "findings_by_type": findings_by_type,
            "top_patterns": sorted(
                [{"id": k, "count": v} for k, v in pattern_counts.items()],
                key=lambda x: x["count"], reverse=True
            )[:10],
        }
    
    return app


# Application instance
app = create_app()
