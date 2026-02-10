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
        
    # Check for reported incidents (reporting actually INCREASES trust slightly as it shows vigilance, 
    # but having many OPEN incidents might decrease it if they are confirmed threats. 
    # For now, let's say reporting is neutral/positive).
    
    # Check for device health if mapped to an endpoint
    if current_user.device_id:
        endpoint = db.query(models.Endpoint).filter(models.Endpoint.id == current_user.device_id).first()
        if endpoint:
            if endpoint.status == 'offline': score -= 10
            if endpoint.risk_level == 'high': score -= 30
            if endpoint.risk_level == 'critical': score -= 50
    
    # Cap score
    return {"trust_score": max(0, min(100, score))}
