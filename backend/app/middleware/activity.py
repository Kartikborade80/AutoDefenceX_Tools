from fastapi import Request
from sqlalchemy.orm import Session
from .. import models, database
from datetime import datetime
import json

async def update_last_activity(request: Request, call_next):
    # Process the request
    response = await call_next(request)
    
    # After response is generated, try to update last activity
    # We do this after response to not block the main request flow
    try:
        # Check if user is authenticated (look for Authorization header)
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            # Get DB session
            db = database.SessionLocal()
            try:
                # We need the user from the token. 
                # Instead of full token decode (expensive), 
                # we can find the session associated with this token if we stored it in DB.
                # In your system, you have session_token in Attendance.
                token = auth_header.split(" ")[1]
                
                # Update the attendance record where session_token matches
                active_session = db.query(models.Attendance).filter(
                    models.Attendance.session_token == token,
                    models.Attendance.is_active == True
                ).first()
                
                if active_session:
                    active_session.last_activity = datetime.utcnow()
                    db.commit()
            finally:
                db.close()
    except Exception as e:
        # Don't fail the request if activity tracking fails
        print(f"Activity Tracking Error: {e}")
        
    return response
