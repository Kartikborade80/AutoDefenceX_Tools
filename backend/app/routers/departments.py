from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from .. import crud, models, schemas, database, auth

router = APIRouter(
    prefix="/departments",
    tags=["departments"],
    responses={404: {"description": "Not found"}},
)

@router.post("/", response_model=schemas.Department)
def create_department(
    department: schemas.DepartmentCreate, 
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Create a new department in current user's organization"""
    # Check if department with this name already exists in this organization
    db_dept = db.query(models.Department).filter(
        models.Department.name == department.name,
        models.Department.organization_id == current_user.organization_id
    ).first()
    if db_dept:
        raise HTTPException(status_code=400, detail="Department already exists")
    
    db_department = models.Department(
        **department.dict(),
        organization_id=current_user.organization_id
    )
    db.add(db_department)
    db.commit()
    db.refresh(db_department)
    return db_department

@router.get("/", response_model=List[schemas.Department])
def list_departments(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """List all departments in current user's organization"""
    departments = db.query(models.Department).filter(
        models.Department.organization_id == current_user.organization_id
    ).offset(skip).limit(limit).all()
    return departments

@router.get("/{department_id}", response_model=schemas.Department)
def read_department(
    department_id: int, 
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Get a specific department by ID"""
    department = db.query(models.Department).filter(
        models.Department.id == department_id,
        models.Department.organization_id == current_user.organization_id
    ).first()
    if department is None:
        raise HTTPException(status_code=404, detail="Department not found")
    return department

@router.put("/{department_id}", response_model=schemas.Department)
def update_department(
    department_id: int, 
    department: schemas.DepartmentCreate, 
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Update a department"""
    db_dept = db.query(models.Department).filter(
        models.Department.id == department_id,
        models.Department.organization_id == current_user.organization_id
    ).first()
    if db_dept is None:
        raise HTTPException(status_code=404, detail="Department not found")
    
    for var, value in department.dict().items():
        setattr(db_dept, var, value)
    
    db.commit()
    db.refresh(db_dept)
    return db_dept

@router.delete("/{department_id}")
def delete_department(
    department_id: int, 
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Delete a department"""
    db_dept = db.query(models.Department).filter(
        models.Department.id == department_id,
        models.Department.organization_id == current_user.organization_id
    ).first()
    if db_dept is None:
        raise HTTPException(status_code=404, detail="Department not found")
    
    db.delete(db_dept)
    db.commit()
    return {"message": "Department deleted successfully"}
