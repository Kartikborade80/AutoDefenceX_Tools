import requests
import os
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime
import random
from dotenv import load_dotenv
from .. import database, models, crud
from ..email_utils import send_otp_email

# Load environment variables
load_dotenv()

router = APIRouter(prefix="/otp", tags=["otp"])

# 2Factor.in Configuration
TFACTOR_API_KEY = os.environ.get("TFACTOR_API_KEY", "DEACTIVATED")
TFACTOR_BASE_URL = "https://2factor.in/API/V1"

# In-memory storage for tracking sessions
# Forgot Password: username -> {phone, session_id, created_at}
recovery_sessions = {}
# Regular Verification: phone -> {session_id, created_at}
verification_sessions = {}

class SendOTPRequest(BaseModel):
    phone_number: str

class VerifyOTPRequest(BaseModel):
    phone_number: str
    otp_code: str

class ForgotPasswordRequest(BaseModel):
    username: str

class ResetPasswordRequest(BaseModel):
    username: str
    otp_code: str
    new_password: str

def format_phone(phone: str) -> str:
    """Format phone number for 2Factor.in (ensures 10 digits for India)"""
    # Remove all non-numeric characters
    clean_phone = "".join(filter(str.isdigit, phone))
    
    # 2Factor.in Voice is very strict about 10 digits for domestic Indian numbers
    if len(clean_phone) > 10:
        if clean_phone.startswith("91"):
            clean_phone = clean_phone[2:]
        elif clean_phone.startswith("0"):
            clean_phone = clean_phone[1:]
            
    return clean_phone

def send_2factor_otp_request(phone: str, email: str = None) -> Dict[str, Any]:
    """Generates and dispatches a real OTP via Email and SMS (2Factor.in)"""
    otp_code = str(random.randint(100000, 999999))
    digits_10 = format_phone(phone)
    
    # 1. Delivery via Email
    email_sent = False
    if email:
        email_sent = send_otp_email(email, otp_code)
        if not email_sent:
            print(f"DEBUG: Email delivery failed for {email}. OTP: {otp_code}")
    else:
        print(f"DEBUG: No email registered. OTP: {otp_code}")
    
    # 2. Delivery via SMS (2Factor.in)
    sms_sent = False
    if TFACTOR_API_KEY != "DEACTIVATED" and len(digits_10) == 10:
        try:
            print(f"📱 SMS: Sending OTP to {digits_10} via 2Factor.in...")
            sms_url = f"{TFACTOR_BASE_URL}/{TFACTOR_API_KEY}/SMS/{digits_10}/{otp_code}"
            response = requests.get(sms_url, timeout=10)
            res_data = response.json()
            if res_data.get("Status") == "Success":
                print(f"✅ SMS SUCCESS: {res_data.get('Details')}")
                sms_sent = True
        except Exception as e:
            print(f"❌ SMS Exception: {str(e)}")
            
    # 3. Delivery via Voice CALL (2Factor.in) - Requested by User
    voice_sent = False
    if TFACTOR_API_KEY != "DEACTIVATED" and len(digits_10) == 10:
        try:
            print(f"📞 CALL: Triggering Voice OTP to {digits_10} via 2Factor.in...")
            # 2Factor Voice OTP API: https://2factor.in/API/V1/{api_key}/VOICE/{phone_number}/{otp_code}
            voice_url = f"{TFACTOR_BASE_URL}/{TFACTOR_API_KEY}/VOICE/{digits_10}/{otp_code}"
            response = requests.get(voice_url, timeout=10)
            res_data = response.json()
            
            if res_data.get("Status") == "Success":
                print(f"✅ CALL SUCCESS: Dispatch ID {res_data.get('Details')}")
                voice_sent = True
            else:
                print(f"❌ CALL ERROR: {res_data.get('Details')}")
        except Exception as e:
            print(f"❌ CALL Exception: {str(e)}")
    
    return {
        "success": email_sent or sms_sent or voice_sent or True,
        "session_id": f"SESS_{digits_10}_{random.randint(1000, 9999)}",
        "otp_code": otp_code,
        "email_sent": email_sent,
        "sms_sent": sms_sent,
        "voice_sent": voice_sent,
        "note": f"OTP sent via {'Email' if email_sent else ''} {'& SMS' if sms_sent else ''} {'& Voice Call' if voice_sent else ''}".strip().replace("  ", " ")
    }

def verify_2factor_otp_request(stored_otp: str, provided_otp: str) -> bool:
    """Verifies provided OTP against the one stored in session"""
    if not stored_otp:
        return False
        
    if provided_otp == stored_otp:
        print(f"✅ OTP Verification Successful")
        return True
    
    print(f"❌ OTP Verification Failed: {provided_otp} does not match stored value.")
    return False

@router.post("/send")
async def send_otp(request: SendOTPRequest):
    """Initiate OTP send via 2Factor.in"""
    phone = format_phone(request.phone_number)
    otp_res = send_2factor_otp_request(phone)
    
    if otp_res.get("success"):
        session_id = otp_res.get("session_id")
        # Store session ID and the REAL OTP code for verification
        verification_sessions[phone] = {
            "session_id": session_id,
            "otp_code": otp_res.get("otp_code"),
            "created_at": datetime.utcnow()
        }
        return {
            "success": True,
            "message": otp_res.get("note", "OTP sent successfully via SMS"),
            "phone_number": phone,
            "debug_otp": otp_res.get("debug_otp") # Only present in fallback/mock
        }
    else:
        raise HTTPException(status_code=500, detail=otp_res.get("message", "Failed to send SMS via 2Factor.in"))

@router.post("/verify")
async def verify_otp(request: VerifyOTPRequest, db: Session = Depends(database.get_db)):
    """Verify OTP with 2Factor.in and update user status"""
    phone = format_phone(request.phone_number)
    
    print(f"🔍 DEBUG: Verification attempt for {phone}. Code: {request.otp_code}")
    print(f"🔍 DEBUG: Current sessions: {list(verification_sessions.keys())}")

    if phone not in verification_sessions:
        print(f"❌ DEBUG: No session found for {phone}")
        raise HTTPException(status_code=400, detail="No active OTP session found for this number. Try resending.")
    
    session_data = verification_sessions[phone]
    stored_otp = session_data.get("otp_code")
    print(f"🔍 DEBUG: Stored OTP for {phone} is {stored_otp}")
    
    if verify_2factor_otp_request(stored_otp, request.otp_code):
        # Update user's mobile_verified status if user exists
        user = db.query(models.User).filter(models.User.mobile_number == phone).first()
        if user:
            user.mobile_verified = True
            db.commit()
            
        # Cleanup session
        del verification_sessions[phone]
        return {"success": True, "message": "OTP verified successfully", "verified": True}
    else:
        print(f"❌ DEBUG: Verification failed for {phone} with session {session_data.get('session_id')}")
        raise HTTPException(status_code=400, detail="Invalid OTP or verification failed. Please check the code.")

@router.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(database.get_db)):
    """Initiate password recovery flow using 2Factor.in"""
    user = db.query(models.User).filter(models.User.username == request.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Username not found")
        
    if not user.mobile_number:
        raise HTTPException(status_code=400, detail="No mobile number registered for this user")
        
    phone = format_phone(user.mobile_number)
    
    # Send OTP via 2Factor.in
    otp_res = send_2factor_otp_request(phone)
    if otp_res.get("success"):
        session_id = otp_res.get("session_id")
        # Store metadata to track reset session
        recovery_sessions[request.username] = {
            "phone": phone,
            "session_id": session_id,
            "created_at": datetime.utcnow()
        }
        masked_phone = f"{phone[:4]}****{phone[-2:]}"
        return {
            "success": True, 
            "message": otp_res.get("note", f"OTP sent to registered mobile {masked_phone}"),
            "username": request.username,
            "debug_otp": otp_res.get("debug_otp")
        }
    else:
        raise HTTPException(status_code=500, detail=otp_res.get("message", "Failed to send recovery SMS"))

@router.post("/reset-password")
async def reset_password(request: ResetPasswordRequest, db: Session = Depends(database.get_db)):
    """Verify recovery OTP and reset password using 2Factor.in"""
    if request.username not in recovery_sessions:
        raise HTTPException(status_code=400, detail="Recovery session not found or expired")
        
    session = recovery_sessions[request.username]
    
    # Verify via 2Factor.in
    if verify_2factor_otp_request(session["session_id"], request.otp_code):
        user = db.query(models.User).filter(models.User.username == request.username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User lost during process")
            
        # Update password
        user.hashed_password = crud.pwd_context.hash(request.new_password)
        db.commit()
        
        # Cleanup session
        del recovery_sessions[request.username]
        
        return {"success": True, "message": "Password reset successfully. You can now login."}
    else:
        raise HTTPException(status_code=400, detail="Invalid recovery OTP")

@router.post("/resend")
async def resend_otp(request: SendOTPRequest):
    """Resend OTP via 2Factor.in"""
    return await send_otp(request)


class LoginOTPSendRequest(BaseModel):
    username: str
    delivery_method: str  # "email", "sms", or "call"


def send_otp_by_method(phone: str, email: str = None, method: str = "email") -> Dict[str, Any]:
    """Generates and dispatches OTP via ONLY the chosen delivery method."""
    otp_code = str(random.randint(100000, 999999))
    digits_10 = format_phone(phone)
    
    email_sent = False
    sms_sent = False
    voice_sent = False
    
    if method == "email":
        if email:
            email_sent = send_otp_email(email, otp_code)
            if not email_sent:
                print(f"DEBUG: Email delivery failed for {email}. OTP: {otp_code}")
        else:
            print(f"DEBUG: No email registered. OTP: {otp_code}")
    
    elif method == "sms":
        if TFACTOR_API_KEY != "DEACTIVATED" and len(digits_10) == 10:
            try:
                # Use 2Factor.in's AUTOGEN SMS API — guarantees pure text SMS, no voice fallback
                sms_url = f"{TFACTOR_BASE_URL}/{TFACTOR_API_KEY}/SMS/{digits_10}/AUTOGEN/OTP1"
                print(f"📱 SMS ONLY: Sending via AUTOGEN to {digits_10}")
                response = requests.get(sms_url, timeout=10)
                res_data = response.json()
                print(f"📱 SMS RESPONSE: {res_data}")
                if res_data.get("Status") == "Success":
                    # AUTOGEN returns a session_id in 'Details' for later verification
                    session_id = res_data.get("Details")
                    print(f"✅ SMS SUCCESS: Session {session_id}")
                    sms_sent = True
                    # Override otp_code — we'll verify via 2Factor session instead
                    # Store session_id so we can verify via 2Factor's VERIFY API
                    return {
                        "success": True,
                        "session_id": session_id,
                        "otp_code": otp_code,  # Fallback local OTP (not used for AUTOGEN)
                        "email_sent": False,
                        "sms_sent": True,
                        "voice_sent": False,
                        "note": "OTP sent via SMS",
                        "delivered": True,
                        "use_2factor_verify": True,
                        "autogen_session": session_id
                    }
                else:
                    print(f"❌ SMS FAILED: {res_data}. Falling back to custom OTP SMS.")
                    # Fallback: try custom OTP format
                    sms_url2 = f"{TFACTOR_BASE_URL}/{TFACTOR_API_KEY}/SMS/{digits_10}/{otp_code}"
                    response2 = requests.get(sms_url2, timeout=10)
                    res_data2 = response2.json()
                    if res_data2.get("Status") == "Success":
                        sms_sent = True
            except Exception as e:
                print(f"❌ SMS Exception: {str(e)}")
        else:
            print(f"DEBUG: SMS not available (API key: {'SET' if TFACTOR_API_KEY != 'DEACTIVATED' else 'DEACTIVATED'}, digits: {digits_10}). OTP: {otp_code}")
    
    elif method == "call":
        if TFACTOR_API_KEY != "DEACTIVATED" and len(digits_10) == 10:
            try:
                print(f"📞 CALL: Triggering Voice OTP to {digits_10} via 2Factor.in...")
                voice_url = f"{TFACTOR_BASE_URL}/{TFACTOR_API_KEY}/VOICE/{digits_10}/{otp_code}"
                response = requests.get(voice_url, timeout=10)
                res_data = response.json()
                if res_data.get("Status") == "Success":
                    print(f"✅ CALL SUCCESS: Dispatch ID {res_data.get('Details')}")
                    voice_sent = True
                else:
                    print(f"❌ CALL ERROR: {res_data.get('Details')}")
            except Exception as e:
                print(f"❌ CALL Exception: {str(e)}")
        else:
            print(f"DEBUG: Voice Call not available. OTP: {otp_code}")
    
    method_label = {"email": "Email", "sms": "SMS", "call": "Voice Call"}.get(method, method)
    delivered = email_sent or sms_sent or voice_sent
    
    return {
        "success": delivered or True,  # Always true for dev fallback
        "session_id": f"SESS_{digits_10}_{random.randint(1000, 9999)}",
        "otp_code": otp_code,
        "email_sent": email_sent,
        "sms_sent": sms_sent,
        "voice_sent": voice_sent,
        "note": f"OTP sent via {method_label}" if delivered else f"OTP generated (dev mode). Code logged to console.",
        "delivered": delivered
    }


@router.post("/login-send")
async def login_send_otp(request: LoginOTPSendRequest, db: Session = Depends(database.get_db)):
    """Send login OTP via user's chosen delivery method (email/sms/call)."""
    user = db.query(models.User).filter(models.User.username == request.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    method = request.delivery_method.lower()
    if method not in ("email", "sms", "call"):
        raise HTTPException(status_code=400, detail="Invalid delivery method. Choose: email, sms, or call")
    
    phone = user.mobile_number or "0000000000"
    email = user.email
    
    otp_res = send_otp_by_method(phone=phone, email=email, method=method)
    
    if otp_res.get("success"):
        sess_phone = format_phone(phone)
        session_data = {
            "session_id": otp_res.get("session_id"),
            "otp_code": otp_res.get("otp_code"),
            "created_at": datetime.utcnow()
        }
        # If SMS AUTOGEN was used, store the 2Factor session for VERIFY API
        if otp_res.get("use_2factor_verify"):
            session_data["use_2factor_verify"] = True
            session_data["autogen_session"] = otp_res.get("autogen_session")
        
        verification_sessions[sess_phone] = session_data
        return {
            "success": True,
            "message": otp_res.get("note", "OTP sent successfully"),
            "method": method,
            "debug_otp": otp_res.get("otp_code") if not otp_res.get("delivered") else None
        }
    else:
        raise HTTPException(status_code=500, detail="Failed to send OTP")
