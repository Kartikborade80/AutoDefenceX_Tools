from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from .. import models, database, auth
from pydantic import BaseModel
from datetime import datetime

router = APIRouter(
    prefix="/reports",
    tags=["reports"]
)

class IncidentCreate(BaseModel):
    type: str
    description: str

class IncidentResponse(BaseModel):
    id: int
    type: str
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True

@router.post("/incident", response_model=IncidentResponse)
def report_incident(incident: IncidentCreate, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """User reports a security incident"""
    new_report = models.IncidentReport(
        user_id=current_user.id,
        type=incident.type,
        description=incident.description,
        status="open"
    )
    db.add(new_report)
    db.commit()
    db.refresh(new_report)
    return new_report

@router.get("/my-score")
def get_my_trust_score(db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """Calculate and return the user's trust score based on activity and device health"""
    # Base score
    score = 100
    
    # Check for recent failed logins
    if current_user.failed_login_attempts > 0:
        score -= (current_user.failed_login_attempts * 5)
        
    # Check for device health if mapped to an endpoint
    if current_user.device_id:
        endpoint = db.query(models.Endpoint).filter(models.Endpoint.id == current_user.device_id).first()
        if endpoint:
            if endpoint.status == 'offline': score -= 10
            if endpoint.risk_level == 'high': score -= 30
            if endpoint.risk_level == 'critical': score -= 50
    
    # Cap score
    return {"trust_score": max(0, min(100, score))}

@router.get("/all-employees")
def get_all_employees_report(db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """Fetch all employees for the organization with summary metrics"""
    users = db.query(models.User).filter(
        models.User.organization_id == current_user.organization_id,
        models.User.is_normal_user == True
    ).all()
    
    total = len(users)
    active = len([u for u in users if u.is_active])
    high_risk = len([u for u in users if u.risk_score > 70])
    avg_score = sum([u.risk_score for u in users]) / total if total > 0 else 0
    
    return {
        "summary": {
            "total_users": total,
            "active_users": active,
            "high_risk_users": high_risk,
            "avg_risk_score": avg_score
        },
        "employees": users
    }

@router.get("/bugs")
def get_bugs_report(db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """Fetch ticket/bug reports for the organization"""
    tickets = db.query(models.Ticket).filter(
        models.Ticket.user.has(organization_id=current_user.organization_id)
    ).order_by(models.Ticket.created_at.desc()).all()
    
    open_count = len([t for t in tickets if t.status in ['open', 'in_progress']])
    resolved_count = len([t for t in tickets if t.status in ['resolved', 'solved', 'completed']])
    critical_count = len([t for t in tickets if 'critical' in (t.description or '').lower()])
    
    return {
        "summary": {
            "total_tickets": len(tickets),
            "open_tickets": open_count,
            "resolved_tickets": resolved_count,
            "critical_tickets": critical_count
        },
        "recent_tickets": tickets
    }

@router.get("/system-health")
def get_system_health_report(db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """Fetch endpoint health statistics"""
    endpoints = db.query(models.Endpoint).filter(
        models.Endpoint.organization_id == current_user.organization_id
    ).all()
    
    total = len(endpoints)
    online = len([e for e in endpoints if e.status == 'online'])
    high_risk = len([e for e in endpoints if e.risk_level in ['high', 'critical']])
    avg_trust = sum([e.trust_score for e in endpoints]) / total if total > 0 else 100
    
    return {
        "summary": {
            "total_endpoints": total,
            "online_endpoints": online,
            "high_risk_endpoints": high_risk,
            "average_trust_score": avg_trust
        }
    }

@router.get("/employee/{user_id}")
def get_single_employee_report(user_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """Fetch detailed security report for a specific employee"""
    user = db.query(models.User).filter(
        models.User.id == user_id,
        models.User.organization_id == current_user.organization_id
    ).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="Employee not found")
        
    activity_count = db.query(models.ActivityLog).filter(models.ActivityLog.user_id == user_id).count()
    incident_count = db.query(models.IncidentReport).filter(models.IncidentReport.user_id == user_id).count()
    
    return {
        "summary": {
            "username": user.username,
            "full_name": user.full_name,
            "risk_score": user.risk_score,
            "total_activities": activity_count,
            "incidents_reported": incident_count,
            "last_login": user.last_login.isoformat() if user.last_login else "Never"
        },
        "user_details": user
    }
