"""Scan endpoints."""

import hashlib
import os
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks

from deployguard.api.schemas import (
    ScanRequest,
    ScanResponse,
    ScanListResponse,
    ScanListItem,
    FindingResponse,
    SeverityLevel,
    FindingType,
    VerificationStatus,
)

router = APIRouter()

# In-memory store for scans (replace with database in production)
_scans: dict[str, dict] = {}


def _finding_to_response(finding, verified: bool = False) -> FindingResponse:
    """Convert a Finding object to FindingResponse."""
    # Handle severity (can be enum or string)
    severity_val = finding.severity
    if hasattr(severity_val, 'value'):
        severity_val = severity_val.value
    try:
        severity = SeverityLevel(severity_val.lower())
    except (ValueError, AttributeError):
        severity = SeverityLevel.medium
    
    # Handle type (can be enum or string)
    type_val = finding.type
    if hasattr(type_val, 'value'):
        type_val = type_val.value
    try:
        finding_type = FindingType(type_val.lower())
    except (ValueError, AttributeError):
        finding_type = FindingType.other
    
    # Redact the matched text for security
    matched = finding.matched_text or ""
    if len(matched) > 8:
        redacted = matched[:4] + "*" * (len(matched) - 8) + matched[-4:]
    else:
        redacted = "*" * len(matched)
    
    return FindingResponse(
        id=hashlib.sha256(f"{finding.file_path}:{finding.line_number}:{finding.pattern_id}".encode()).hexdigest()[:16],
        file_path=finding.file_path,
        line_number=finding.line_number,
        pattern_id=finding.pattern_id,
        pattern_name=finding.pattern_name or finding.pattern_id,
        severity=severity,
        finding_type=finding_type,
        matched_text=redacted,
        context=finding.context,
        verification_status=VerificationStatus(finding.verification_status) if finding.verification_status else None,
        commit_hash=getattr(finding, 'commit_hash', None),
        author=getattr(finding, 'author', None),
    )


async def _run_scan(scan_id: str, request: ScanRequest):
    """Background task to run the scan."""
    from deployguard.core.scanner import SecretScanner
    from deployguard.core.verifier import SecretVerifier
    
    try:
        _scans[scan_id]["status"] = "running"
        
        # Configure scanner
        scanner = SecretScanner()
        
        # Run scan on the path
        if os.path.isfile(request.path):
            with open(request.path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            findings = scanner.scan_file(request.path, content)
        elif os.path.isdir(request.path):
            findings = scanner.scan_directory(
                directory=request.path,
                file_includes=request.include_extensions,
                file_excludes=request.exclude_extensions,
            )
        else:
            raise ValueError(f"Path not found: {request.path}")
        
        # Verify secrets if requested
        if request.verify_secrets and findings:
            verifier = SecretVerifier()
            results = await verifier.verify_findings(findings)
            # Update findings with verification status
            for result in results:
                result.finding.verification_status = result.status.value
            findings = [r.finding for r in results]
        
        # Convert findings to responses
        finding_responses = [_finding_to_response(f, request.verify_secrets) for f in findings]
        
        # Calculate summary
        summary = {
            "by_severity": {},
            "by_type": {},
            "verified_active": 0,
            "verified_inactive": 0,
        }
        for f in finding_responses:
            sev = f.severity.value
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
            ftype = f.finding_type.value
            summary["by_type"][ftype] = summary["by_type"].get(ftype, 0) + 1
            if f.verification_status == VerificationStatus.active:
                summary["verified_active"] += 1
            elif f.verification_status == VerificationStatus.inactive:
                summary["verified_inactive"] += 1
        
        # Update scan record
        _scans[scan_id].update({
            "status": "completed",
            "completed_at": datetime.utcnow(),
            "total_files": getattr(scanner, 'files_scanned', 0),
            "total_findings": len(finding_responses),
            "findings": finding_responses,
            "summary": summary,
        })
        
    except Exception as e:
        _scans[scan_id].update({
            "status": "failed",
            "completed_at": datetime.utcnow(),
            "error": str(e),
        })


@router.post("/scan", response_model=ScanResponse)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks) -> ScanResponse:
    """
    Start a new scan.
    
    Initiates a scan of the specified path and returns immediately.
    Use GET /scan/{scan_id} to check the status and get results.
    """
    scan_id = str(uuid.uuid4())
    
    scan_record = {
        "scan_id": scan_id,
        "status": "pending",
        "path": request.path,
        "started_at": datetime.utcnow(),
        "completed_at": None,
        "total_files": 0,
        "total_findings": 0,
        "findings": [],
        "summary": {},
    }
    _scans[scan_id] = scan_record
    
    # Start scan in background
    background_tasks.add_task(_run_scan, scan_id, request)
    
    return ScanResponse(**scan_record)


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str) -> ScanResponse:
    """
    Get scan results by ID.
    
    Returns the current status and findings for a scan.
    """
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    scan = _scans[scan_id]
    return ScanResponse(
        scan_id=scan["scan_id"],
        status=scan["status"],
        path=scan["path"],
        started_at=scan["started_at"],
        completed_at=scan.get("completed_at"),
        total_files=scan.get("total_files", 0),
        total_findings=scan.get("total_findings", 0),
        findings=scan.get("findings", []),
        summary=scan.get("summary", {}),
    )


@router.get("/scans", response_model=ScanListResponse)
async def list_scans(
    limit: int = 20,
    offset: int = 0,
    status: Optional[str] = None,
) -> ScanListResponse:
    """
    List all scans.
    
    Returns a paginated list of scans with optional status filtering.
    """
    scans = list(_scans.values())
    
    # Filter by status
    if status:
        scans = [s for s in scans if s["status"] == status]
    
    # Sort by start time (newest first)
    scans.sort(key=lambda s: s["started_at"], reverse=True)
    
    # Paginate
    total = len(scans)
    scans = scans[offset:offset + limit]
    
    items = [
        ScanListItem(
            scan_id=s["scan_id"],
            path=s["path"],
            status=s["status"],
            started_at=s["started_at"],
            completed_at=s.get("completed_at"),
            total_findings=s.get("total_findings", 0),
        )
        for s in scans
    ]
    
    return ScanListResponse(scans=items, total=total)


@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str) -> dict:
    """
    Delete a scan by ID.
    
    Removes the scan record from storage.
    """
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    del _scans[scan_id]
    return {"deleted": True, "scan_id": scan_id}
