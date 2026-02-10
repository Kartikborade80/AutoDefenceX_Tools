from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
from .. import crud, models, schemas, database, auth

router = APIRouter(
    prefix="/policies",
    tags=["policies"],
    responses={404: {"description": "Not found"}},
)

@router.post("/", response_model=schemas.Policy)
def create_policy(
    policy: schemas.PolicyCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_admin_user)
):
    """Create a new policy (Admin only)"""
    # Check permissions: Head Admin can create for any department, others only for their own
    if not current_user.is_head_admin and policy.department_id != current_user.department_id:
        raise HTTPException(status_code=403, detail="You can only create policies for your department")
    
    db_policy = models.Policy(
        **policy.dict(),
        organization_id=current_user.organization_id
    )
    db.add(db_policy)
    db.commit()
    db.refresh(db_policy)
    return db_policy

@router.get("/", response_model=List[schemas.Policy])
def list_policies(
    skip: int = 0,
    limit: int = 100,
    department_id: int = None,
    user_id: int = None,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """List all policies (filtered by department if not head admin)"""
    query = db.query(models.Policy).filter(
        models.Policy.organization_id == current_user.organization_id
    )
    
    # Filter by user if specified
    if user_id:
        query = query.filter(models.Policy.applied_to_user_id == user_id)
    # Filter by department if specified or if user is not head admin
    elif department_id:
        query = query.filter(models.Policy.department_id == department_id)
    elif not current_user.is_head_admin and current_user.department_id:
        query = query.filter(models.Policy.department_id == current_user.department_id)
    
    policies = query.offset(skip).limit(limit).all()
    return policies

@router.get("/{policy_id}", response_model=schemas.Policy)
def get_policy(
    policy_id: int,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Get a specific policy"""
    policy = db.query(models.Policy).filter(
        models.Policy.id == policy_id,
        models.Policy.organization_id == current_user.organization_id
    ).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found or access denied")
    
    # Check permissions
    if not current_user.is_head_admin and policy.department_id != current_user.department_id:
        raise HTTPException(status_code=403, detail="You can only view policies from your department")
    
    return policy

@router.put("/{policy_id}", response_model=schemas.Policy)
def update_policy(
    policy_id: int,
    policy_update: schemas.PolicyUpdate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_admin_user)
):
    """Update a policy (Admin only)"""
    policy = db.query(models.Policy).filter(
        models.Policy.id == policy_id,
        models.Policy.organization_id == current_user.organization_id
    ).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found or access denied")
    
    # Check permissions
    if not current_user.is_head_admin and policy.department_id != current_user.department_id:
        raise HTTPException(status_code=403, detail="You can only update policies from your department")
    
    for key, value in policy_update.dict(exclude_unset=True).items():
        setattr(policy, key, value)
    
    db.commit()
    db.refresh(policy)
    return policy

@router.delete("/{policy_id}")
def delete_policy(
    policy_id: int,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_admin_user)
):
    """Delete a policy (Admin only)"""
    policy = db.query(models.Policy).filter(
        models.Policy.id == policy_id,
        models.Policy.organization_id == current_user.organization_id
    ).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found or access denied")
    
    # Check permissions
    if not current_user.is_head_admin and policy.department_id != current_user.department_id:
        raise HTTPException(status_code=403, detail="You can only delete policies from your department")
    
    db.delete(policy)
    db.commit()
    return {"message": "Policy deleted successfully"}

@router.post("/{policy_id}/apply/{user_id}")
def apply_policy_to_user(
    policy_id: int,
    user_id: int,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_admin_user)
):
    """Apply a policy to a specific user"""
    policy = db.query(models.Policy).filter(models.Policy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check permissions
    if not current_user.is_head_admin:
        if policy.department_id != current_user.department_id or user.department_id != current_user.department_id:
            raise HTTPException(status_code=403, detail="Permission denied")
    
    policy.applied_to_user_id = user_id
    db.commit()
    db.refresh(policy)
    return {"message": f"Policy applied to user {user_id}"}

@router.post("/propagate")
def propagate_policies(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_admin_user)
):
    """Broadcasting policy update to all active agents"""
    # Create activity log
    crud.create_activity_log(db, schemas.ActivityLogCreate(
        action="policy_propagation",
        details={"scope": "global", "admin": current_user.username}
    ), user_id=current_user.id)
    
    # Broadcast via WebSockets
    try:
        from ..websockets import manager
        import asyncio
        asyncio.create_task(manager.broadcast_to_org(current_user.organization_id, {
            "type": "policy_update",
            "data": {
                "status": "enforcing",
                "timestamp": datetime.now().isoformat()
            }
        }))
    except Exception as e:
        print(f"Broadcast error: {e}")
        
    return {"message": "Policy propagation signal sent to all agents"}
