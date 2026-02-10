from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import models, schemas, database

router = APIRouter(
    prefix="/organizations",
    tags=["organizations"]
)

@router.get("/by-username/{username}")
def get_organization_by_username(username: str, db: Session = Depends(database.get_db)):
    """
    Get organization information by username.
    Used for live company name display during login.
    """
    user = db.query(models.User).filter(models.User.username == username).first()
    
    if user and user.organization:
        return {
            "exists": True,
            "organization_name": user.organization.name,
            "organization_id": user.organization.id,
            "user_role": user.role,
            "full_name": user.full_name,
            "department_name": user.department.name if user.department else None,
            "risk_score": user.risk_score
        }
    elif user:
        # User exists but no organization (system admin)
        return {
            "exists": True,
            "organization_name": "System Administration",
            "organization_id": None,
            "user_role": user.role,
            "full_name": user.full_name,
            "department_name": "Management",
            "risk_score": user.risk_score
        }
    
    return {
        "exists": False,
        "organization_name": None,
        "organization_id": None,
        "full_name": None,
        "department_name": None,
        "risk_score": None
    }

@router.get("/", response_model=List[schemas.Organization])
def get_organizations(db: Session = Depends(database.get_db)):
    """Get all organizations (system admin only)"""
    return db.query(models.Organization).all()

@router.get("/{org_id}", response_model=schemas.Organization)
def get_organization(org_id: int, db: Session = Depends(database.get_db)):
    """Get specific organization"""
    org = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org
