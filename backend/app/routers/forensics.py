from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from .. import crud, models, schemas, database, auth

router = APIRouter(
    prefix="/forensics",
    tags=["forensics"],
    responses={404: {"description": "Not found"}},
)

@router.post("/", response_model=schemas.ForensicLog)
def create_forensic_log(
    log: schemas.ForensicLogCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Create a forensic log entry"""
    db_log = models.ForensicLog(**log.dict())
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

@router.get("/", response_model=List[schemas.ForensicLog])
def list_forensic_logs(
    skip: int = 0,
    limit: int = 100,
    user_id: Optional[int] = Query(None),
    event_type: Optional[str] = Query(None),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_admin_user)
):
    """List forensic logs with optional filters (Admin only)"""
    query = db.query(models.ForensicLog).join(models.User).filter(
        models.User.organization_id == current_user.organization_id
    )
    
    # Department Scoping
    if not current_user.is_head_admin:
        if current_user.department_id:
            query = query.filter(models.User.department_id == current_user.department_id)
        else:
            # If they have no department and aren't head admin, they see nothing
            return []
    
    # Apply filters
    if user_id:
        query = query.filter(models.ForensicLog.user_id == user_id)
    if event_type:
        query = query.filter(models.ForensicLog.event_type == event_type)
    if start_date:
        start_dt = datetime.fromisoformat(start_date)
        query = query.filter(models.ForensicLog.timestamp >= start_dt)
    if end_date:
        end_dt = datetime.fromisoformat(end_date)
        query = query.filter(models.ForensicLog.timestamp <= end_dt)
    
    # Order by most recent first
    query = query.order_by(models.ForensicLog.timestamp.desc())
    
    logs = query.offset(skip).limit(limit).all()
    return logs

@router.get("/user/{user_id}", response_model=List[schemas.ForensicLog])
def get_user_forensic_logs(
    user_id: int,
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_admin_user)
):
    """Get all forensic logs for a specific user (Admin only)"""
    logs = db.query(models.ForensicLog).join(models.User).filter(
        models.User.id == user_id,
        models.User.organization_id == current_user.organization_id
    ).order_by(models.ForensicLog.timestamp.desc()).offset(skip).limit(limit).all()
    
    return logs

@router.get("/stats")
def get_forensic_stats(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_admin_user)
):
    """Get forensic statistics (Admin only)"""
    org_id = current_user.organization_id
    
    total_logs = db.query(models.ForensicLog).join(models.User).filter(
        models.User.organization_id == org_id
    ).count()
    
    # Count by event type
    event_types = db.query(
        models.ForensicLog.event_type,
        func.count(models.ForensicLog.id)
    ).join(models.User).filter(
        models.User.organization_id == org_id
    ).group_by(models.ForensicLog.event_type).all()
    
    event_type_counts = {event_type: count for event_type, count in event_types}
    
    # Recent failed logins
    failed_logins = db.query(models.ForensicLog).join(models.User).filter(
        models.ForensicLog.event_type == 'failed_login',
        models.User.organization_id == org_id
    ).order_by(models.ForensicLog.timestamp.desc()).limit(10).all()
    
    return {
        "total_logs": total_logs,
        "event_type_counts": event_type_counts,
        "recent_failed_logins": [
            {
                "user_id": log.user_id,
                "timestamp": log.timestamp.isoformat(),
                "ip_address": log.ip_address,
                "details": log.details
            }
            for log in failed_logins
        ]
    }
