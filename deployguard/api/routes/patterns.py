"""Pattern management endpoints."""

from typing import Optional

from fastapi import APIRouter, HTTPException

from deployguard.api.schemas import (
    PatternResponse,
    PatternListResponse,
    SeverityLevel,
    FindingType,
)

router = APIRouter()


def _pattern_to_response(pattern) -> PatternResponse:
    """Convert a SecretPattern object to PatternResponse."""
    # Handle severity
    severity_val = pattern.severity
    if hasattr(severity_val, 'value'):
        severity_val = severity_val.value
    try:
        severity = SeverityLevel(str(severity_val).lower())
    except (ValueError, AttributeError):
        severity = SeverityLevel.medium
    
    # Handle type
    type_val = pattern.secret_type
    if hasattr(type_val, 'value'):
        type_val = type_val.value
    try:
        pattern_type = FindingType(str(type_val).lower())
    except (ValueError, AttributeError):
        pattern_type = FindingType.other
    
    return PatternResponse(
        id=pattern.name.lower().replace(" ", "_").replace("-", "_"),
        name=pattern.name,
        description=getattr(pattern, 'description', None),
        severity=severity,
        pattern_type=pattern_type,
        enabled=True,
    )


@router.get("/patterns", response_model=PatternListResponse)
async def list_patterns(
    severity: Optional[str] = None,
    pattern_type: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> PatternListResponse:
    """
    List all available patterns.
    
    Returns a paginated list of patterns with optional filtering.
    """
    from deployguard.core.scanner import SecretScanner
    
    scanner = SecretScanner()
    patterns = scanner.patterns
    
    # Filter by severity
    if severity:
        severity_lower = severity.lower()
        patterns = [
            p for p in patterns
            if (p.severity.value if hasattr(p.severity, 'value') else str(p.severity)).lower() == severity_lower
        ]
    
    # Filter by type
    if pattern_type:
        type_lower = pattern_type.lower()
        patterns = [
            p for p in patterns
            if (p.secret_type.value if hasattr(p.secret_type, 'value') else str(p.secret_type)).lower() == type_lower
        ]
    
    # Search in name and description
    if search:
        search_lower = search.lower()
        patterns = [
            p for p in patterns
            if search_lower in p.name.lower() or 
               (hasattr(p, 'description') and p.description and search_lower in p.description.lower())
        ]
    
    # Get total before pagination
    total = len(patterns)
    
    # Paginate
    patterns = patterns[offset:offset + limit]
    
    # Convert to response
    pattern_responses = [_pattern_to_response(p) for p in patterns]
    
    return PatternListResponse(patterns=pattern_responses, total=total)


@router.get("/patterns/{pattern_id}", response_model=PatternResponse)
async def get_pattern(pattern_id: str) -> PatternResponse:
    """
    Get a specific pattern by ID.
    """
    from deployguard.core.scanner import SecretScanner
    
    scanner = SecretScanner()
    
    for pattern in scanner.patterns:
        pid = pattern.name.lower().replace(" ", "_").replace("-", "_")
        if pid == pattern_id:
            return _pattern_to_response(pattern)
    
    raise HTTPException(status_code=404, detail=f"Pattern {pattern_id} not found")


@router.get("/patterns/stats/summary")
async def get_patterns_summary() -> dict:
    """
    Get a summary of patterns by severity and type.
    """
    from deployguard.core.scanner import SecretScanner
    
    scanner = SecretScanner()
    patterns = scanner.patterns
    
    by_severity = {}
    by_type = {}
    
    for pattern in patterns:
        # Count by severity
        sev = pattern.severity
        if hasattr(sev, 'value'):
            sev = sev.value
        sev = str(sev).lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        
        # Count by type
        ptype = pattern.secret_type
        if hasattr(ptype, 'value'):
            ptype = ptype.value
        ptype = str(ptype).lower()
        by_type[ptype] = by_type.get(ptype, 0) + 1
    
    return {
        "total": len(patterns),
        "by_severity": by_severity,
        "by_type": by_type,
    }
