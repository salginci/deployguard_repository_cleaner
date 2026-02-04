"""Secret verification endpoints."""

import asyncio
from fastapi import APIRouter, HTTPException

from deployguard.api.schemas import VerifyRequest, VerifyResponse, VerificationStatus

router = APIRouter()


@router.post("/verify", response_model=VerifyResponse)
async def verify_secrets(request: VerifyRequest) -> VerifyResponse:
    """
    Verify if secrets are active.
    
    Takes a list of secrets and checks if they are currently active/valid.
    Each secret should have 'type' and 'value' keys at minimum.
    
    Example request body:
    ```json
    {
        "secrets": [
            {"type": "github_token", "value": "ghp_xxxxx"},
            {"type": "aws_access_key", "value": "AKIA...", "secret_key": "..."}
        ],
        "timeout": 10
    }
    ```
    """
    from deployguard.core.verifier import SecretVerifier
    
    if not request.secrets:
        return VerifyResponse(verified=0, results=[])
    
    verifier = SecretVerifier(timeout=request.timeout)
    results = []
    
    for secret in request.secrets:
        secret_type = secret.get("type", "").lower()
        secret_value = secret.get("value", "")
        
        if not secret_type or not secret_value:
            results.append({
                "type": secret_type,
                "status": VerificationStatus.error.value,
                "message": "Missing type or value",
            })
            continue
        
        try:
            # Map secret types to verifier methods
            is_active = await verifier.verify_secret(secret_type, secret_value, secret)
            
            if is_active is None:
                status = VerificationStatus.unknown
                message = "Verification not supported for this type"
            elif is_active:
                status = VerificationStatus.active
                message = "Secret is active"
            else:
                status = VerificationStatus.inactive
                message = "Secret is inactive or invalid"
            
            results.append({
                "type": secret_type,
                "status": status.value,
                "message": message,
            })
            
        except asyncio.TimeoutError:
            results.append({
                "type": secret_type,
                "status": VerificationStatus.error.value,
                "message": "Verification timed out",
            })
        except Exception as e:
            results.append({
                "type": secret_type,
                "status": VerificationStatus.error.value,
                "message": str(e),
            })
    
    return VerifyResponse(verified=len(results), results=results)


@router.get("/verify/types")
async def list_verification_types() -> dict:
    """
    List supported secret types for verification.
    
    Returns a list of secret types that can be verified.
    """
    from deployguard.core.verifier import SecretVerifier
    
    verifier = SecretVerifier()
    supported_types = verifier.get_supported_types()
    
    return {
        "types": supported_types,
        "total": len(supported_types),
    }
