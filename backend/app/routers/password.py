from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import datetime
from .. import database, models, auth, crud
from ..security_utils import validate_password_strength
from passlib.context import CryptContext

router = APIRouter(prefix="/password", tags=["password"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class ForcedChangePasswordRequest(BaseModel):
    username: str
    old_password: str
    new_password: str

class ChangePasswordResponse(BaseModel):
    success: bool
    message: str

@router.post("/change", response_model=ChangePasswordResponse)
async def change_password(
    request: ChangePasswordRequest,
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """
    Change user password with validation:
    - Verify old password
    - Validate new password strength
    - Check against password history (last 5 passwords)
    - Update password and reset security flags
    """
    
    # Verify old password
    if not pwd_context.verify(request.old_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Validate new password strength with user info
    validation = validate_password_strength(
        request.new_password,
        user_full_name=current_user.full_name,
        username=current_user.username
    )
    if not validation["valid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=validation["message"]
        )
    
    # Check if new password is same as old password
    if pwd_context.verify(request.new_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password cannot be the same as your current password"
        )
    
    # Check password history (last 5 passwords)
    password_history = db.query(models.PasswordHistory)\
        .filter(models.PasswordHistory.user_id == current_user.id)\
        .order_by(models.PasswordHistory.created_at.desc())\
        .limit(5)\
        .all()
    
    for old_password in password_history:
        if pwd_context.verify(request.new_password, old_password.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot reuse any of your last 5 passwords"
            )
    
    # Save current password to history
    password_history_entry = models.PasswordHistory(
        user_id=current_user.id,
        hashed_password=current_user.hashed_password,
        created_at=datetime.utcnow()
    )
    db.add(password_history_entry)
    
    # Update user password
    current_user.hashed_password = pwd_context.hash(request.new_password)
    current_user.password_changed_at = datetime.utcnow()
    current_user.must_change_password = False
    current_user.failed_login_attempts = 0
    current_user.account_locked_until = None
    
    db.commit()
    
    return ChangePasswordResponse(
        success=True,
        message="Password changed successfully"
    )

@router.post("/change-forced", response_model=ChangePasswordResponse)
async def change_password_forced(
    request: ForcedChangePasswordRequest,
    db: Session = Depends(database.get_db)
):
    """
    Change password for users who are forced to change (no authentication required).
    Used when user doesn't have a valid token yet.
    Verifies identity using username + old password.
    """
    # Find user by username
    user = crud.get_user(db, request.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Verify old password
    if not pwd_context.verify(request.old_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Validate new password strength with user info
    validation = validate_password_strength(
        request.new_password,
        user_full_name=user.full_name,
        username=user.username
    )
    if not validation["valid"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=validation["message"]
        )
    
    # Check if new password is same as old password
    if pwd_context.verify(request.new_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password cannot be the same as your current password"
        )
    
    # Check password history (last 5 passwords)
    password_history = db.query(models.PasswordHistory)\
        .filter(models.PasswordHistory.user_id == user.id)\
        .order_by(models.PasswordHistory.created_at.desc())\
        .limit(5)\
        .all()
    
    for old_password in password_history:
        if pwd_context.verify(request.new_password, old_password.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot reuse any of your last 5 passwords"
            )
    
    # Save current password to history
    password_history_entry = models.PasswordHistory(
        user_id=user.id,
        hashed_password=user.hashed_password,
        created_at=datetime.utcnow()
    )
    db.add(password_history_entry)
    
    # Update user password
    user.hashed_password = pwd_context.hash(request.new_password)
    user.password_changed_at = datetime.utcnow()
    user.must_change_password = False
    user.failed_login_attempts = 0
    user.account_locked_until = None
    
    db.commit()
    
    return ChangePasswordResponse(
        success=True,
        message="Password changed successfully"
    )


@router.get("/check-expiry")
async def check_password_expiry(
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """
    Check if user's password has expired or needs to be changed
    """
    from datetime import timedelta
    
    password_age_days = 0
    if current_user.password_changed_at:
        password_age = datetime.utcnow() - current_user.password_changed_at
        password_age_days = password_age.days
    
    expiry_days = current_user.password_expiry_days or 30
    is_expired = password_age_days >= expiry_days
    
    return {
        "must_change": current_user.must_change_password or is_expired,
        "password_age_days": password_age_days,
        "expiry_days": expiry_days,
        "is_expired": is_expired,
        "failed_attempts": current_user.failed_login_attempts
    }
