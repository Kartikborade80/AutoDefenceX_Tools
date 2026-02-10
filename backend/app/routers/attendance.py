from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import models, schemas, auth, database
from datetime import datetime

router = APIRouter(prefix="/attendance", tags=["attendance"])

@router.post("/", response_model=schemas.Attendance)
def log_attendance(attendance: schemas.AttendanceCreate, db: Session = Depends(database.get_db)):
    db_attendance = models.Attendance(**attendance.dict())
    if not db_attendance.login_time:
        db_attendance.login_time = datetime.utcnow()
    db.add(db_attendance)
    db.commit()
    db.refresh(db_attendance)
    return db_attendance

@router.get("/current/{user_id}")
def get_current_session(user_id: int, db: Session = Depends(database.get_db)):
    """Get current active attendance session for quick status checks"""
    active = db.query(models.Attendance).filter(
        models.Attendance.user_id == user_id,
        models.Attendance.is_active == True
    ).first()
    
    if active:
        duration_hours = (datetime.utcnow() - active.login_time).total_seconds() / 3600.0
        return {
            "status": "on_duty",
            "login_time": active.login_time,
            "duration_hours": duration_hours
        }
    return {"status": "offline", "login_time": None, "duration_hours": 0}

@router.get("/{user_id}", response_model=List[schemas.Attendance])
def get_user_attendance(user_id: int, db: Session = Depends(database.get_db)):
    """Get all attendance records for a user, sorted by most recent first"""
    return db.query(models.Attendance).filter(
        models.Attendance.user_id == user_id
    ).order_by(models.Attendance.login_time.desc()).all()

@router.put("/{attendance_id}", response_model=schemas.Attendance)
def update_attendance(attendance_id: int, attendance_update: schemas.AttendanceUpdate, db: Session = Depends(database.get_db)):
    db_attendance = db.query(models.Attendance).filter(models.Attendance.id == attendance_id).first()
    if not db_attendance:
        raise HTTPException(status_code=404, detail="Attendance record not found")
    
    update_data = attendance_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_attendance, key, value)
    
    if db_attendance.logout_time and db_attendance.login_time:
        diff = db_attendance.logout_time - db_attendance.login_time
        db_attendance.working_hours = diff.total_seconds() / 3600.0

    db.commit()
    db.refresh(db_attendance)
    return db_attendance

@router.get("/department/{dept_id}", response_model=List[schemas.Attendance])
def get_department_attendance(dept_id: int, db: Session = Depends(database.get_db),
                              current_user: models.User = Depends(auth.get_current_active_user)):
    # Verify permission: Admin or Head of THIS department
    if current_user.role != 'admin':
        if not (current_user.is_department_head and current_user.department_id == dept_id):
            raise HTTPException(status_code=403, detail="Not authorized to view this department's attendance")
            
    # Fetch all users in department
    dept_users = db.query(models.User).filter(models.User.department_id == dept_id).all()
    user_ids = [u.id for u in dept_users]
    
    return db.query(models.Attendance).filter(models.Attendance.user_id.in_(user_ids)).all()

@router.post("/heartbeat")
def update_activity(
    current_user: models.User = Depends(auth.get_current_active_user),
    db: Session = Depends(database.get_db)
):
    """Update last activity timestamp for current session"""
    active_session = db.query(models.Attendance).filter(
        models.Attendance.user_id == current_user.id,
        models.Attendance.is_active == True
    ).first()
    
    if active_session:
        active_session.last_activity = datetime.utcnow()
        db.commit()
        return {"status": "ok", "last_activity": active_session.last_activity}
    
    return {"status": "no_active_session"}
