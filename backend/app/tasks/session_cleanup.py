"""
Background task for cleaning up inactive attendance sessions.
Automatically logs out users who have been inactive for more than the specified timeout period.
"""
from datetime import datetime, timedelta
from ..database import SessionLocal
from .. import models

# Configuration
INACTIVITY_TIMEOUT_MINUTES = 15

def cleanup_inactive_sessions():
    """
    Auto-logout sessions inactive for more than INACTIVITY_TIMEOUT_MINUTES.
    This function should be called periodically (e.g., every 5 minutes) by a scheduler.
    """
    db = SessionLocal()
    try:
        cutoff_time = datetime.utcnow() - timedelta(minutes=INACTIVITY_TIMEOUT_MINUTES)
        
        # Find all active sessions with last_activity older than cutoff
        inactive_sessions = db.query(models.Attendance).filter(
            models.Attendance.is_active == True,
            models.Attendance.last_activity < cutoff_time
        ).all()
        
        # Auto-logout each inactive session
        for session in inactive_sessions:
            session.logout_time = datetime.utcnow()
            session.is_active = False
            session.logout_reason = 'inactivity'
            if session.login_time:
                duration = session.logout_time - session.login_time
                session.working_hours = duration.total_seconds() / 3600.0
        
        if inactive_sessions:
            db.commit()
            print(f"✅ Session Cleanup: Logged out {len(inactive_sessions)} inactive sessions")
        
    except Exception as e:
        print(f"❌ Session Cleanup Error: {e}")
        db.rollback()
    finally:
        db.close()
