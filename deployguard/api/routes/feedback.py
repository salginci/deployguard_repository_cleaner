"""
DeployGuard API - Feedback Routes

Receives anonymized user feedback on secret detection to improve ML models.

Security measures:
- HMAC signature validation
- Rate limiting per client ID
- Data structure validation
- Timestamp freshness check
"""
import json
import os
import hmac
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, validator

from fastapi import APIRouter, HTTPException, Request, Header

router = APIRouter()

# Feedback storage directory
FEEDBACK_STORAGE_DIR = os.environ.get(
    "DEPLOYGUARD_FEEDBACK_STORAGE",
    os.path.expanduser("~/.deployguard/server_feedback")
)

# Rate limiting: max requests per client per hour
RATE_LIMIT_MAX_REQUESTS = 100
RATE_LIMIT_WINDOW_HOURS = 1

# In-memory rate limit tracking (use Redis in production)
_rate_limit_cache: Dict[str, List[datetime]] = {}

# Public salt for signature validation (must match CLI)
PUBLIC_SALT = "deployguard-feedback-v1-2024"


class SecretFeedbackItem(BaseModel):
    """Anonymized secret feedback item."""
    value_hash: str
    secret_type: str
    severity: str
    value_length: int
    value_pattern: str
    file_extension: Optional[str] = ""
    file_type: Optional[str] = "unknown"
    
    @validator('value_hash')
    def validate_hash(cls, v):
        if not v or len(v) < 8:
            raise ValueError('Invalid value_hash')
        return v
    
    @validator('value_length')
    def validate_length(cls, v):
        if v < 0 or v > 10000:
            raise ValueError('Invalid value_length')
        return v


class FeedbackSummary(BaseModel):
    """Feedback summary statistics."""
    total_detected: int
    confirmed_secrets: int
    false_positives: int
    false_positive_rate: float
    
    @validator('total_detected', 'confirmed_secrets', 'false_positives')
    def validate_counts(cls, v):
        if v < 0 or v > 10000:
            raise ValueError('Invalid count')
        return v


class FeedbackSubmission(BaseModel):
    """Feedback submission from CLI."""
    timestamp: str
    version: Optional[str] = "1.0.0"
    client_id: Optional[str] = None
    confirmed_secrets: List[SecretFeedbackItem]
    false_positives: List[SecretFeedbackItem]
    summary: FeedbackSummary
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        try:
            ts = datetime.fromisoformat(v.replace('Z', '+00:00'))
            # Reject timestamps more than 1 hour old or in the future
            now = datetime.now()
            if ts > now + timedelta(hours=1):
                raise ValueError('Timestamp in the future')
            if ts < now - timedelta(hours=1):
                raise ValueError('Timestamp too old')
        except (ValueError, TypeError) as e:
            if 'Timestamp' in str(e):
                raise
            raise ValueError('Invalid timestamp format')
        return v
    
    @validator('confirmed_secrets', 'false_positives')
    def validate_list_size(cls, v):
        if len(v) > 1000:
            raise ValueError('Too many items in list')
        return v


class FeedbackResponse(BaseModel):
    """Response to feedback submission."""
    status: str
    message: str
    stats: Dict[str, int]


def _verify_signature(
    data: dict,
    signature: str,
    client_id: str,
    timestamp: str
) -> bool:
    """
    Verify HMAC signature from CLI.
    
    Returns True if signature is valid.
    """
    if not signature or not client_id:
        return False
    
    # Recreate signing payload (must match CLI)
    signing_payload = json.dumps({
        "timestamp": timestamp,
        "confirmed_count": len(data.get("confirmed_secrets", [])),
        "false_positive_count": len(data.get("false_positives", [])),
        "client_id": client_id,
    }, sort_keys=True)
    
    # Generate expected signature
    expected_signature = hmac.new(
        PUBLIC_SALT.encode(),
        signing_payload.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(signature, expected_signature)


def _check_rate_limit(client_id: str) -> bool:
    """
    Check if client is within rate limits.
    
    Returns True if request is allowed.
    """
    if not client_id:
        return False
    
    now = datetime.now()
    window_start = now - timedelta(hours=RATE_LIMIT_WINDOW_HOURS)
    
    # Get client's request history
    if client_id not in _rate_limit_cache:
        _rate_limit_cache[client_id] = []
    
    # Clean old entries
    _rate_limit_cache[client_id] = [
        ts for ts in _rate_limit_cache[client_id]
        if ts > window_start
    ]
    
    # Check limit
    if len(_rate_limit_cache[client_id]) >= RATE_LIMIT_MAX_REQUESTS:
        return False
    
    # Record this request
    _rate_limit_cache[client_id].append(now)
    
    return True


@router.post("/feedback", response_model=FeedbackResponse, tags=["Feedback"])
async def receive_feedback(
    feedback: FeedbackSubmission,
    request: Request,
    x_client_id: Optional[str] = Header(None, alias="X-Client-ID"),
    x_signature: Optional[str] = Header(None, alias="X-Signature"),
    x_timestamp: Optional[str] = Header(None, alias="X-Timestamp"),
):
    """
    Receive anonymized feedback from CLI users.
    
    Security:
    - Validates HMAC signature
    - Rate limits per client ID
    - Validates data structure
    - Checks timestamp freshness
    
    Privacy: No actual secret values are received - only hashes and patterns.
    """
    try:
        feedback_data = feedback.dict()
        
        # Use header client_id or fallback to body
        client_id = x_client_id or feedback_data.get("client_id")
        
        # Verify signature (skip in development mode)
        if not os.environ.get("DEPLOYGUARD_DEV_MODE"):
            if not _verify_signature(feedback_data, x_signature, client_id, x_timestamp or feedback.timestamp):
                raise HTTPException(
                    status_code=401,
                    detail="Invalid request signature"
                )
        
        # Check rate limit
        if not _check_rate_limit(client_id):
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded. Please try again later."
            )
        
        # Validate data consistency
        expected_total = len(feedback.confirmed_secrets) + len(feedback.false_positives)
        if feedback.summary.total_detected != expected_total:
            raise HTTPException(
                status_code=400,
                detail="Data inconsistency: total_detected doesn't match items"
            )
        
        # Add server metadata
        feedback_data["received_at"] = datetime.utcnow().isoformat()
        feedback_data["client_ip_hash"] = hashlib.sha256(
            (request.client.host or "unknown").encode()
        ).hexdigest()[:16]
        
        # Store feedback
        _store_feedback(feedback_data)
        
        # Update aggregated statistics
        _update_statistics(feedback_data)
        
        return FeedbackResponse(
            status="success",
            message="Thank you for your feedback! This helps improve detection accuracy.",
            stats={
                "confirmed_secrets": len(feedback.confirmed_secrets),
                "false_positives": len(feedback.false_positives),
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/feedback/stats", tags=["Feedback"])
async def get_feedback_stats():
    """
    Get aggregated feedback statistics.
    
    Returns overall statistics on detection accuracy based on user feedback.
    """
    stats_file = os.path.join(FEEDBACK_STORAGE_DIR, "aggregated_stats.json")
    
    if os.path.exists(stats_file):
        with open(stats_file) as f:
            stats = json.load(f)
        return stats
    
    return {
        "total_feedback_submissions": 0,
        "total_confirmed_secrets": 0,
        "total_false_positives": 0,
        "overall_false_positive_rate": 0,
        "top_false_positive_patterns": [],
        "top_true_positive_patterns": [],
    }


@router.get("/feedback/patterns", tags=["Feedback"])
async def get_known_patterns():
    """
    Get known false positive patterns based on aggregated feedback.
    
    CLI can use this to pre-filter likely false positives.
    """
    patterns_file = os.path.join(FEEDBACK_STORAGE_DIR, "known_false_positives.json")
    
    if os.path.exists(patterns_file):
        with open(patterns_file) as f:
            patterns = json.load(f)
        return patterns
    
    # Default known false positive patterns
    return {
        "patterns": [
            {"pattern": "sha256/[alnum:43]+[special:1]", "confidence": 0.95, "reason": "SSL certificate pin"},
            {"pattern": "http://schemas.android.com", "confidence": 0.99, "reason": "Android XML namespace"},
            {"pattern": "android.support.", "confidence": 0.95, "reason": "Android library reference"},
            {"pattern": "androidx.", "confidence": 0.95, "reason": "AndroidX library reference"},
        ],
        "updated_at": datetime.utcnow().isoformat(),
    }


def _store_feedback(feedback_data: dict) -> None:
    """Store feedback to disk for later ML training."""
    os.makedirs(FEEDBACK_STORAGE_DIR, exist_ok=True)
    
    # Create daily feedback file
    date_str = datetime.utcnow().strftime("%Y%m%d")
    feedback_file = os.path.join(FEEDBACK_STORAGE_DIR, f"feedback_{date_str}.jsonl")
    
    # Append to JSONL file (one JSON object per line)
    with open(feedback_file, "a") as f:
        f.write(json.dumps(feedback_data) + "\n")


def _update_statistics(feedback_data: dict) -> None:
    """Update aggregated statistics."""
    os.makedirs(FEEDBACK_STORAGE_DIR, exist_ok=True)
    stats_file = os.path.join(FEEDBACK_STORAGE_DIR, "aggregated_stats.json")
    
    # Load existing stats or create new
    if os.path.exists(stats_file):
        with open(stats_file) as f:
            stats = json.load(f)
    else:
        stats = {
            "total_feedback_submissions": 0,
            "total_confirmed_secrets": 0,
            "total_false_positives": 0,
            "pattern_counts": {
                "true_positives": {},
                "false_positives": {},
            },
            "file_type_counts": {
                "true_positives": {},
                "false_positives": {},
            },
            "secret_type_counts": {
                "true_positives": {},
                "false_positives": {},
            },
        }
    
    # Update counts
    stats["total_feedback_submissions"] += 1
    stats["total_confirmed_secrets"] += len(feedback_data.get("confirmed_secrets", []))
    stats["total_false_positives"] += len(feedback_data.get("false_positives", []))
    
    # Calculate overall false positive rate
    total = stats["total_confirmed_secrets"] + stats["total_false_positives"]
    if total > 0:
        stats["overall_false_positive_rate"] = round(
            stats["total_false_positives"] / total * 100, 2
        )
    
    # Track patterns for true positives
    for secret in feedback_data.get("confirmed_secrets", []):
        pattern = secret.get("value_pattern", "unknown")
        stats["pattern_counts"]["true_positives"][pattern] = \
            stats["pattern_counts"]["true_positives"].get(pattern, 0) + 1
        
        file_type = secret.get("file_type", "unknown")
        stats["file_type_counts"]["true_positives"][file_type] = \
            stats["file_type_counts"]["true_positives"].get(file_type, 0) + 1
        
        secret_type = secret.get("secret_type", "unknown")
        stats["secret_type_counts"]["true_positives"][secret_type] = \
            stats["secret_type_counts"]["true_positives"].get(secret_type, 0) + 1
    
    # Track patterns for false positives
    for secret in feedback_data.get("false_positives", []):
        pattern = secret.get("value_pattern", "unknown")
        stats["pattern_counts"]["false_positives"][pattern] = \
            stats["pattern_counts"]["false_positives"].get(pattern, 0) + 1
        
        file_type = secret.get("file_type", "unknown")
        stats["file_type_counts"]["false_positives"][file_type] = \
            stats["file_type_counts"]["false_positives"].get(file_type, 0) + 1
        
        secret_type = secret.get("secret_type", "unknown")
        stats["secret_type_counts"]["false_positives"][secret_type] = \
            stats["secret_type_counts"]["false_positives"].get(secret_type, 0) + 1
    
    # Compute top patterns
    stats["top_false_positive_patterns"] = sorted(
        stats["pattern_counts"]["false_positives"].items(),
        key=lambda x: -x[1]
    )[:20]
    
    stats["top_true_positive_patterns"] = sorted(
        stats["pattern_counts"]["true_positives"].items(),
        key=lambda x: -x[1]
    )[:20]
    
    stats["updated_at"] = datetime.utcnow().isoformat()
    
    # Save stats
    with open(stats_file, "w") as f:
        json.dump(stats, f, indent=2)
    
    # Update known false positive patterns if we have enough data
    _update_known_false_positives(stats)


def _update_known_false_positives(stats: dict) -> None:
    """
    Update the known false positives file based on aggregated data.
    
    A pattern is considered a "known false positive" if:
    - It has been marked as false positive more than 10 times
    - Its false positive rate is > 80%
    """
    patterns_file = os.path.join(FEEDBACK_STORAGE_DIR, "known_false_positives.json")
    
    known_patterns = []
    
    fp_counts = stats["pattern_counts"]["false_positives"]
    tp_counts = stats["pattern_counts"]["true_positives"]
    
    for pattern, fp_count in fp_counts.items():
        tp_count = tp_counts.get(pattern, 0)
        total = fp_count + tp_count
        
        if total >= 10:  # Need at least 10 samples
            fp_rate = fp_count / total
            if fp_rate > 0.8:  # 80% false positive rate
                known_patterns.append({
                    "pattern": pattern,
                    "confidence": round(fp_rate, 2),
                    "sample_count": total,
                    "reason": "User feedback indicates this is usually not a secret",
                })
    
    # Sort by confidence
    known_patterns.sort(key=lambda x: -x["confidence"])
    
    result = {
        "patterns": known_patterns,
        "updated_at": datetime.utcnow().isoformat(),
        "total_samples": stats["total_feedback_submissions"],
    }
    
    with open(patterns_file, "w") as f:
        json.dump(result, f, indent=2)
