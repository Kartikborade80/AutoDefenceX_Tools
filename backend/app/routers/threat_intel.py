from fastapi import APIRouter, Depends, HTTPException
from .. import auth, schemas, models
from ..threat_intel import AlienVaultOTX

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])

@router.get("/lookup/{indicator_type}/{indicator}")
def lookup_indicator(indicator_type: str, indicator: str, 
                     current_user: models.User = Depends(auth.get_current_active_user)):
    """
    Lookup an indicator (ip, domain, file) in AlienVault OTX.
    """
    result = AlienVaultOTX.get_indicator_details(indicator_type, indicator)
    if "error" in result:
        raise HTTPException(status_code=502, detail=result["error"])
    return result
