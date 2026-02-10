from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
from .. import crud, models, schemas, database, auth

router = APIRouter(
    prefix="/sessions",
    tags=["sessions"],
    responses={404: {"description": "Not found"}},
)

@router.post("/", response_model=schemas.EndpointSession)
def create_session(
    session: schemas.EndpointSessionCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Create a new endpoint session"""
    # End any existing active sessions for this user/endpoint
    existing_sessions = db.query(models.EndpointSession).filter(
        models.EndpointSession.user_id == session.user_id,
        models.EndpointSession.endpoint_id == session.endpoint_id,
        models.EndpointSession.is_active == True
    ).all()
    
    for existing in existing_sessions:
        existing.is_active = False
        existing.session_end = datetime.utcnow()
    
    # Create new session
    db_session = models.EndpointSession(**session.dict())
    db.add(db_session)
    db.commit()
    db.refresh(db_session)
    return db_session

@router.get("/", response_model=List[schemas.EndpointSession])
def list_sessions(
    skip: int = 0,
    limit: int = 100,
    active_only: bool = True,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_admin_user)
):
    """List all endpoint sessions (Admin only)"""
    # Join with User to filter by organization
    query = db.query(models.EndpointSession).join(models.User).filter(
        models.User.organization_id == current_user.organization_id
    )
    
    if active_only:
        query = query.filter(models.EndpointSession.is_active == True)
    
    sessions = query.order_by(models.EndpointSession.session_start.desc()).offset(skip).limit(limit).all()
    return sessions

@router.post("/{session_id}/heartbeat")
def update_heartbeat(
    session_id: int,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Update session heartbeat"""
    session = db.query(models.EndpointSession).filter(models.EndpointSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session.last_heartbeat = datetime.utcnow()
    db.commit()
    db.refresh(session)
    
    return {
        "message": "Heartbeat updated",
        "last_heartbeat": session.last_heartbeat.isoformat()
    }

@router.post("/{session_id}/end")
def end_session(
    session_id: int,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_admin_user)
):
    """End an active session (Admin only)"""
    session = db.query(models.EndpointSession).filter(models.EndpointSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session.is_active = False
    session.session_end = datetime.utcnow()
    db.commit()
    
    return {"message": "Session ended successfully"}

@router.get("/active")
def get_active_sessions(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_admin_user)
):
    """Get all active sessions with user and endpoint details (Admin only)"""
    # Join with User to filter by organization
    sessions = db.query(models.EndpointSession).join(models.User).filter(
        models.User.organization_id == current_user.organization_id,
        models.EndpointSession.is_active == True
    ).all()
    
    result = []
    for session in sessions:
        user = db.query(models.User).filter(models.User.id == session.user_id).first()
        endpoint = db.query(models.Endpoint).filter(models.Endpoint.id == session.endpoint_id).first()
        
        result.append({
            "session_id": session.id,
            "user_name": user.full_name if user else "Unknown",
            "user_id": session.user_id,
            "endpoint_hostname": endpoint.hostname if endpoint else "Unknown",
            "endpoint_id": session.endpoint_id,
            "session_start": session.session_start.isoformat(),
            "last_heartbeat": session.last_heartbeat.isoformat(),
            "duration_seconds": (datetime.utcnow() - session.session_start).total_seconds()
        })
    
    return result
