from fastapi import Depends, HTTPException, status
from . import models, auth

async def get_current_admin_user(current_user: models.User = Depends(auth.get_current_active_user)):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Not enough privileges. Admin role required."
        )
    return current_user

async def get_current_power_user(current_user: models.User = Depends(auth.get_current_active_user)):
    """User who can perform actions but not manage other users."""
    if current_user.role not in ["admin", "user"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Not enough privileges. User role required."
        )
    return current_user

async def get_current_viewer_user(current_user: models.User = Depends(auth.get_current_active_user)):
    """Read-only access."""
    # All active users are at least viewers
    return current_user
