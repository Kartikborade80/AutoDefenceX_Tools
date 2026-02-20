import os
from fastapi import APIRouter, Depends, HTTPException, status, Form, Request, BackgroundTasks
from typing import Optional
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
from .. import crud, models, schemas, database, auth

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/token", response_model=schemas.TokenResponse)
async def login_for_access_token(
    request: Request,
    background_tasks: BackgroundTasks,
    username: str = Form(...),
    password: str = Form(...),
    otp: Optional[str] = Form(None),
    db: Session = Depends(database.get_db)
):
    from .otp import send_2factor_otp_request, verify_2factor_otp_request, verification_sessions, format_phone
    from datetime import datetime, timedelta

    # Capture IP and User-Agent
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")

    # Get user first to check for account lock
    db_user = crud.get_user(db, username=username)
    if db_user:
        # Check if account is locked
        if db_user.account_locked_until and db_user.account_locked_until > datetime.utcnow():
            # Log failed attempt due to lock
            attempt = models.LoginAttempt(
                username=username,
                ip_address=client_ip,
                success=False,
                user_agent=user_agent,
                failure_reason="account_locked"
            )
            db.add(attempt)
            db.commit()
            
            wait_time = int((db_user.account_locked_until - datetime.utcnow()).total_seconds() / 60)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is locked. Please try again in {wait_time} minutes or contact support."
            )

    user = crud.authenticate_user(db, username, password)
    if not user:
        # Log failed login attempt
        if db_user:
            # Increment failed attempts
            db_user.failed_login_attempts += 1
            db_user.last_failed_login = datetime.utcnow()
            
            # Lock account after 5 failed attempts
            # Force password change after 30 failed attempts
            reason = "incorrect_password"
            if db_user.failed_login_attempts >= 30:
                db_user.must_change_password = True
                reason = "password_change_required_attempts"
            elif db_user.failed_login_attempts >= 5:
                db_user.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
                reason = "account_locked_due_to_attempts"
            
            # Log to ForensicLog (security audit)
            forensic_log = models.ForensicLog(
                user_id=db_user.id,
                event_type="failed_login",
                ip_address=client_ip,
                details={"username": username, "reason": reason, "attempts": db_user.failed_login_attempts}
            )
            db.add(forensic_log)
            
            # Log to ActivityLog (user activity tracking)
            activity_log = models.ActivityLog(
                user_id=db_user.id,
                action="failed_login",
                details={"username": username, "reason": reason}
            )
            db.add(activity_log)
            
            # Log to LoginAttempt
            attempt = models.LoginAttempt(
                username=username,
                ip_address=client_ip,
                success=False,
                user_agent=user_agent,
                failure_reason=reason
            )
            db.add(attempt)
            db.commit()
        else:
            # User doesn't exist, still log to LoginAttempt for pattern monitoring
            attempt = models.LoginAttempt(
                username=username,
                ip_address=client_ip,
                success=False,
                user_agent=user_agent,
                failure_reason="user_not_found"
            )
            db.add(attempt)
            db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Successful password match
    # Check if user is using default password (Pass@123)
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    # List of default passwords to check
    default_passwords = ["Pass@123", "Pass123", "Password@123", "Password123"]
    using_default_password = any(pwd_context.verify(default_pwd, user.hashed_password) for default_pwd in default_passwords)
    
    if using_default_password:
        # Set flag but allow login
        user.must_change_password = True
        db.commit()
    
    # Check password expiry (30 days)
    password_expired = False
    if user.password_changed_at:
        password_age = datetime.utcnow() - user.password_changed_at
        password_expired = password_age.days >= (user.password_expiry_days or 30)
    
    # Set must_change_password if expired
    if password_expired:
        user.must_change_password = True
        db.commit()
    
    # Reset failed attempts if successful
    user.failed_login_attempts = 0
    user.account_locked_until = None
    db.commit()

    
    # Check if user is Admin and needs OTP
    if user.role == "admin":
        if not otp:
            phone = format_phone(user.mobile_number) if user.mobile_number else "N/A"
            
            # TRIGGER REAL OTP DISPATCH
            # If user has no phone, we can't send SMS, but we can try Email
            otp_res = send_2factor_otp_request(
                phone=user.mobile_number if user.mobile_number else "0000000000",
                email=user.email
            )
            
            if otp_res.get("success"):
                # Store the session for the verification step
                # We use phone as the key in verification_sessions
                sess_phone = format_phone(user.mobile_number) if user.mobile_number else "0000000000"
                verification_sessions[sess_phone] = {
                    "session_id": otp_res.get("session_id"),
                    "otp_code": otp_res.get("otp_code"),
                    "created_at": datetime.utcnow()
                }
            
            return {
                "access_token": "",
                "token_type": "bearer",
                "otp_required": True,
                "phone_masked": f"{phone[:3]}****{phone[-3:]}" if phone != "N/A" else "Admin MFA",
                "user_info": None,
                "note": "A 6-digit verification code has been sent to your registered email/phone."
            }
        else:
            # Verify REAL OTP
            phone = format_phone(user.mobile_number) if user.mobile_number else "0000000000"
            
            # DEMO BYPASS: Allow 000000 if email password is not set
            is_demo_mode = not os.environ.get("EMAIL_PASSWORD")
            if is_demo_mode and otp == "000000":
                print(f"⚠️ Security: Admin {user.username} used DEMO OTP bypass (000000)")
            elif phone in verification_sessions:
                session_data = verification_sessions[phone]
                if not verify_2factor_otp_request(session_data["otp_code"], otp):
                    raise HTTPException(status_code=401, detail="Invalid Security OTP")
                
                # Success! Cleanup session
                del verification_sessions[phone]
                print(f"✅ Security: Admin {user.username} verified using Real OTP")
            else:
                raise HTTPException(status_code=401, detail="OTP session expired or not found. Please login again.")
    
    # Update last login time
    crud.update_last_login(db, user.id)
    
    # Log successful login
    try:
        # Log to ForensicLog (security audit)
        forensic_log = models.ForensicLog(
            user_id=user.id,
            event_type="login",
            ip_address=client_ip,
            details={"username": user.username, "role": user.role, "user_agent": user_agent}
        )
        db.add(forensic_log)
        
        # Log to ActivityLog (user activity tracking for UI display)
        activity_log = models.ActivityLog(
            user_id=user.id,
            action="login",
            details={
                "username": user.username, 
                "role": user.role,
                "login_method": "password" + (" + OTP" if user.role == "admin" else ""),
                "ip": client_ip
            }
        )
        db.add(activity_log)
        
        # Log to LoginAttempt
        attempt = models.LoginAttempt(
            username=user.username,
            ip_address=client_ip,
            success=True,
            user_agent=user_agent
        )
        db.add(attempt)
        
        # SINGLE SESSION ENFORCEMENT: Auto-logout previous active sessions
        import secrets
        active_sessions = db.query(models.Attendance).filter(
            models.Attendance.user_id == user.id,
            models.Attendance.is_active == True
        ).all()
        
        for session in active_sessions:
            session.logout_time = datetime.utcnow()
            session.is_active = False
            session.logout_reason = 'new_session'
            if session.login_time:
                duration = session.logout_time - session.login_time
                session.working_hours = duration.total_seconds() / 3600.0
        
        # Create new attendance record with session tracking
        import secrets
        session_token = secrets.token_urlsafe(32)
        device_info = auth.parse_user_agent(user_agent)
        attendance_record = models.Attendance(
            user_id=user.id,
            login_time=datetime.utcnow(),
            status='present',
            session_token=session_token,
            last_activity=datetime.utcnow(),
            is_active=True,
            ip_address=client_ip,
            user_agent=user_agent,
            browser_name=device_info["browser_name"],
            browser_version=device_info["browser_version"],
            os_name=device_info["os_name"],
            os_version=device_info["os_version"]
        )
        db.add(attendance_record)

        db.add(attendance_record)
        db.commit()
    except Exception as e:
        print(f"ERROR LOGGING LOGIN: {e}")
        db.rollback() # Important to rollback if commit failed
        # Continue login process even if logging fails
    
    
    # 📧 Email Notification: Send alert to the user
    from ..email_utils import send_login_email_alert
    from ..utils.geolocation import get_location_from_ip
    
    client_ip = request.client.host
    login_time_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    location = get_location_from_ip(client_ip)
    
    # Priority: User's Profile Email > Testing/Admin Email
    recipient = user.email if user.email else "autodefense.x@gmail.com"
    
    background_tasks.add_task(
        send_login_email_alert, 
        username=user.username, 
        login_time=login_time_str, 
        ip_address=client_ip,
        location=location,
        recipient_email=recipient
    )

    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires
    )
    
    # Get organization info if user belongs to one
    company_name = None
    company_domain = None
    if user.organization_id:
        org = db.query(models.Organization).filter(models.Organization.id == user.organization_id).first()
        if org:
            company_name = org.name
            company_domain = org.domain
    
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user_info": {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "full_name": user.full_name,
            "organization_id": user.organization_id,
            "department_id": user.department_id,
            "is_department_head": user.is_department_head,
            "is_normal_user": user.is_normal_user,
            "company_name": company_name,
            "company_domain": company_domain,
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "must_change_password": user.must_change_password  # Flag for dashboard
        }
    }

@router.post("/logout")
def logout(current_user: models.User = Depends(auth.get_current_active_user), db: Session = Depends(database.get_db)):
    """Logs out the user and updates attendance record"""
    from datetime import datetime
    
    # Find latest open attendance record
    record = db.query(models.Attendance).filter(
        models.Attendance.user_id == current_user.id, 
        models.Attendance.logout_time == None
    ).order_by(models.Attendance.login_time.desc()).first()
    
    if record:
        record.logout_time = datetime.utcnow()
        record.is_active = False
        record.logout_reason = 'manual'
        # Calculate working hours
        duration = record.logout_time - record.login_time
        record.working_hours = duration.total_seconds() / 3600.0
        db.commit()
        
    return {"message": "Logged out successfully"}

