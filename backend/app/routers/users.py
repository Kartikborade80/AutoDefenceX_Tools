from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from .. import crud, models, schemas, database, auth, rbac

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={404: {"description": "Not found"}},
)

@router.post("/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(database.get_db), 
                current_user: models.User = Depends(auth.get_current_active_user)):
    # Permission Check
    if current_user.role != 'admin':
        if not current_user.is_department_head:
            raise HTTPException(status_code=403, detail="Not authorized to create users")
        
        # Dept Head Logic: Force department and organization match
        user.organization_id = current_user.organization_id
        user.department_id = current_user.department_id
        user.role = "user" # Force role to be standard user
        user.is_head_admin = False
    
    db_user = crud.get_user(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Pass organization_id (either from admin or dept head enforced above)
    # Pass organization_id (either from admin or dept head enforced above)
    org_id = user.organization_id if user.organization_id else current_user.organization_id
    return crud.create_user(db=db, user=user, organization_id=org_id)

@router.post("/register-public", response_model=schemas.User)
def register_public(user: schemas.PublicUserCreate, db: Session = Depends(database.get_db)):
    db_user = crud.get_user(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
        
    return crud.create_public_user(db=db, user=user)
    return crud.create_public_user(db=db, user=user)

@router.post("/register-admin", response_model=schemas.User)
def register_admin(admin: schemas.AdminRegisterCreate, db: Session = Depends(database.get_db)):
    try:
        db_user = crud.get_user(db, username=admin.username)
        if db_user:
            raise HTTPException(status_code=400, detail="Username already registered")
            
        return crud.create_admin_user(db=db, admin=admin)
        return crud.create_admin_user(db=db, admin=admin)
    except Exception as e:
        import traceback
        with open("router_error_log.txt", "w") as f:
            f.write(traceback.format_exc())
        raise e

@router.get("/", response_model=List[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db), 
               current_user: models.User = Depends(auth.get_current_admin_or_hod)):
    # Organization-level filtering (multi-tenancy)
    # Department Scoping within organization
    if current_user.is_head_admin or not current_user.department_id:
        # Head admin or Admin without department assignment sees all users in their organization
        users = crud.get_users(db, organization_id=current_user.organization_id, skip=skip, limit=limit)
    else:
        # Admin assigned to a department sees users in their own department
        users = db.query(models.User).filter(
            models.User.organization_id == current_user.organization_id,
            models.User.department_id == current_user.department_id
        ).offset(skip).limit(limit).all()
    return users

@router.put("/{user_id}", response_model=schemas.User)
def update_user(user_id: int, user_update: schemas.UserUpdate, db: Session = Depends(database.get_db),
                current_user: models.User = Depends(rbac.get_current_admin_user)):
    try:
        db_user = crud.update_user(db, user_id=user_id, user_update=user_update)
        if not db_user:
            raise HTTPException(status_code=404, detail="User not found")
        return db_user
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/me", response_model=schemas.User)
async def read_users_me(current_user: models.User = Depends(auth.get_current_active_user)):
    return current_user

@router.get("/active", response_model=List[schemas.User])
def read_active_users(department_id: int = None, db: Session = Depends(database.get_db), 
               current_user: models.User = Depends(auth.get_current_active_user)):
    """Get all active users for ticket assignment, scoped by organization and optionally department"""
    query = db.query(models.User).filter(
        models.User.is_active == True,
        models.User.organization_id == current_user.organization_id
    )
    
    if department_id:
        query = query.filter(models.User.department_id == department_id)
    # If it's a specific admin requesting without explicit dept, still scope to their dept if they have one
    elif current_user.role == 'admin' and not current_user.is_head_admin:
        if current_user.department_id:
            query = query.filter(models.User.department_id == current_user.department_id)
            
    users = query.all()
    return users

# --- Tickets ---
@router.post("/tickets", response_model=schemas.Ticket)
def create_ticket(ticket: schemas.TicketCreate, db: Session = Depends(database.get_db),
                  current_user: models.User = Depends(auth.get_current_active_user)):
    return crud.create_ticket(db=db, ticket=ticket, user_id=current_user.id)

@router.get("/tickets", response_model=List[schemas.Ticket])
def read_tickets(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db),
                 current_user: models.User = Depends(auth.get_current_active_user)):
    # Admins see all in their org, Users see theirs
    if current_user.role == "admin":
        return crud.get_tickets(db, organization_id=current_user.organization_id, skip=skip, limit=limit)
    return crud.get_tickets(db, user_id=current_user.id, skip=skip, limit=limit)

@router.patch("/tickets/{ticket_id}")
def update_ticket_status(ticket_id: int, status_update: dict, db: Session = Depends(database.get_db),
                         current_user: models.User = Depends(auth.get_current_active_user)):
    ticket = db.query(models.Ticket).filter(models.Ticket.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    if 'status' in status_update:
        ticket.status = status_update['status']
    db.commit()
    db.refresh(ticket)
    return ticket

# --- Activity Internal API (Used by Agent/Frontend) ---
@router.post("/activity", response_model=schemas.ActivityLog)
def log_user_activity(activity: schemas.ActivityLogCreate, db: Session = Depends(database.get_db),
                      current_user: models.User = Depends(auth.get_current_active_user)):
    return crud.create_activity_log(db=db, activity=activity, user_id=current_user.id)

@router.get("/{user_id}/activity", response_model=List[schemas.ActivityLog])
def read_user_activity(user_id: int, db: Session = Depends(database.get_db),
                       current_user: models.User = Depends(auth.get_current_admin_or_hod)):
    return crud.get_activity_logs(db, user_id=user_id)

@router.post("/{user_id}/unlock")
def unlock_user(user_id: int, db: Session = Depends(database.get_db),
                current_user: models.User = Depends(rbac.get_current_admin_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.account_locked_until = None
    user.failed_login_attempts = 0
    db.commit()
    return {"message": "User account unlocked successfully"}

@router.get("/security/login-attempts", response_model=List[schemas.LoginAttempt])
def read_login_attempts(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db),
                        current_user: models.User = Depends(rbac.get_current_admin_user)):
    return db.query(models.LoginAttempt).order_by(models.LoginAttempt.timestamp.desc()).offset(skip).limit(limit).all()

@router.get("/security/alerts", response_model=List[schemas.SecurityAlert])
def read_security_alerts(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db),
                         current_user: models.User = Depends(rbac.get_current_admin_user)):
    return db.query(models.SecurityAlert).order_by(models.SecurityAlert.timestamp.desc()).offset(skip).limit(limit).all()

@router.post("/security/alerts/{alert_id}/resolve")
def resolve_security_alert(alert_id: int, db: Session = Depends(database.get_db),
                           current_user: models.User = Depends(rbac.get_current_admin_user)):
    alert = db.query(models.SecurityAlert).filter(models.SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_resolved = True
    db.commit()
    return {"message": "Alert resolved"}
