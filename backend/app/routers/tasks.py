from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import models, schemas, auth, database
from datetime import datetime

router = APIRouter(prefix="/tasks", tags=["tasks"])

@router.post("/", response_model=schemas.Task)
def create_task(task: schemas.TaskCreate, db: Session = Depends(database.get_db),
                current_user: models.User = Depends(auth.get_current_active_user)):
    # Restrict to Admin or Department Head
    if not (current_user.role == 'admin' or current_user.is_department_head):
        raise HTTPException(status_code=403, detail="Only Department Heads or Admins can assign tasks")

    db_task = models.Task(**task.dict())
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task

@router.get("/assigned-to/{user_id}", response_model=List[schemas.Task])
def get_assigned_tasks(user_id: int, db: Session = Depends(database.get_db)):
    return db.query(models.Task).filter(models.Task.assigned_to_id == user_id).all()

@router.get("/assigned-by/{user_id}", response_model=List[schemas.Task])
def get_created_tasks(user_id: int, db: Session = Depends(database.get_db)):
    return db.query(models.Task).filter(models.Task.assigned_by_id == user_id).all()

@router.put("/{task_id}", response_model=schemas.Task)
def update_task_status(task_id: int, task_update: schemas.TaskUpdate, db: Session = Depends(database.get_db)):
    db_task = db.query(models.Task).filter(models.Task.id == task_id).first()
    if not db_task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    db_task.status = task_update.status
    if task_update.status == "completed":
        db_task.completed_at = datetime.utcnow()
    
    db.commit()
    db.refresh(db_task)
    return db_task

@router.delete("/{task_id}")
def delete_task(task_id: int, db: Session = Depends(database.get_db), 
                current_user: models.User = Depends(auth.get_current_active_user)):
    db_task = db.query(models.Task).filter(models.Task.id == task_id).first()
    if not db_task:
        raise HTTPException(status_code=404, detail="Task not found")

    # Optional: Check permission (e.g., only creator or admin)
    if not (current_user.role == 'admin' or db_task.assigned_by_id == current_user.id):
         raise HTTPException(status_code=403, detail="Not authorized to delete this task")

    db.delete(db_task)
    db.commit()
    return {"message": "Task deleted successfully"}
