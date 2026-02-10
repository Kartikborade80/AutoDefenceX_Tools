from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import crud, models, schemas, database, auth, rbac
import subprocess
import asyncio
from datetime import datetime

router = APIRouter(
    prefix="/endpoints",
    tags=["endpoints"],
    responses={404: {"description": "Not found"}},
)

@router.post("/", response_model=schemas.Endpoint)
def register_endpoint(endpoint: schemas.EndpointCreate, db: Session = Depends(database.get_db),
                      current_user: models.User = Depends(auth.get_current_active_user)):
    # In a real scenario, we might want to restrict who can register endpoints
    # or have a handshake mechanism.
    # Pass organization_id from current session user
    return crud.create_endpoint(db=db, endpoint=endpoint, organization_id=current_user.organization_id)

@router.get("/{endpoint_id}", response_model=schemas.EndpointDetail)
def read_endpoint(endpoint_id: int, db: Session = Depends(database.get_db),
                  current_user: models.User = Depends(auth.get_current_active_user)):
    db_endpoint = crud.get_endpoint_details(db, endpoint_id=endpoint_id)
    if db_endpoint is None:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    # Security Check: Ensure the endpoint belongs to the user's organization
    if db_endpoint.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Not authorized to view this endpoint")
        
    return db_endpoint

@router.get("/", response_model=List[schemas.ConnectedEndpoint])
def read_endpoints(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db),
                   current_user: models.User = Depends(auth.get_current_active_user)): 
    
    # 1. Base Query: Only Active Sessions linked to current Org
    query = db.query(models.EndpointSession).filter(
        models.EndpointSession.is_active == True
    ).join(models.User).filter(
        models.User.organization_id == current_user.organization_id
    )

    # 2. Filter by department if requesting user is a restricted Admin
    if current_user.role == 'admin' and not current_user.is_head_admin:
        if current_user.department_id:
            query = query.filter(models.User.department_id == current_user.department_id)

    sessions = query.offset(skip).limit(limit).all()
    
    # 3. Map to ConnectedEndpoint schema
    results = []
    for s in sessions:
        results.append({
            "session_id": s.id,
            "endpoint_id": s.endpoint_id,
            "user_id": s.user_id,
            "hostname": s.endpoint.hostname,
            "ip_address": s.endpoint.ip_address,
            "full_name": s.user.full_name,
            "employee_id": s.user.employee_id,
            "department_name": s.user.department.name if s.user.department else "N/A",
            "job_title": s.user.job_title or "Employee",
            "session_start": s.session_start,
            "status": "online"
        })
        
    return results

async def isolate_endpoint_logic(endpoint_id: int, db: Session, current_user: models.User, reason: str = "Manual Admin Action"):
    """Core logic to isolate an endpoint"""
    endpoint = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if not endpoint:
        return False
        
    endpoint.status = "isolated"
    db.commit()
    
    crud.create_activity_log(db, schemas.ActivityLogCreate(
        action="isolate_endpoint",
        details={"hostname": endpoint.hostname, "id": endpoint.id, "reason": reason}
    ), user_id=current_user.id)
    
    # Broadcast containment alert
    try:
        from ..websockets import manager
        await manager.broadcast_to_org(current_user.organization_id, {
            "type": "containment_event",
            "data": {
                "endpoint_id": endpoint_id,
                "hostname": endpoint.hostname,
                "status": "isolated",
                "reason": reason,
                "timestamp": datetime.now().isoformat()
            }
        })
    except Exception as e:
        print(f"Broadcast failed: {e}")
        
    return True

@router.post("/{endpoint_id}/isolate")
async def isolate_endpoint(endpoint_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """Manually isolate an endpoint"""
    endpoint = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    if endpoint.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    success = await isolate_endpoint_logic(endpoint_id, db, current_user, reason=f"Manual Action by {current_user.email}")
    if not success:
         raise HTTPException(status_code=500, detail="Isolation failed")
         
    return {"message": f"Endpoint {endpoint.hostname} isolated successfully", "status": "isolated"}

@router.post("/{endpoint_id}/restore")
async def restore_endpoint(endpoint_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """Restore a previously isolated endpoint"""
    endpoint = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
        
    if endpoint.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Not authorized")
        
    endpoint.status = "online"
    # Reset risk if it was isolated due to risk
    if endpoint.risk_level == "critical":
        endpoint.risk_level = "high" # Downgrade but keep watch
        
    db.commit()
    
    crud.create_activity_log(db, schemas.ActivityLogCreate(
        action="restore_endpoint",
        details={"hostname": endpoint.hostname, "id": endpoint.id}
    ), user_id=current_user.id)
    
    # Notify
    try:
        from ..websockets import manager
        await manager.broadcast_to_org(current_user.organization_id, {
            "type": "containment_event",
            "data": {
                "endpoint_id": endpoint_id,
                "hostname": endpoint.hostname,
                "status": "online",
                "reason": f"Restored by {current_user.email}",
                "timestamp": datetime.now().isoformat()
            }
        })
    except Exception as e:
        print(f"Broadcast failed: {e}")

    return {"message": f"Endpoint {endpoint.hostname} restored successfully", "status": "online"}

async def kill_process_logic(endpoint_id: int, pid: int, db: Session, current_user: models.User):
    """Core logic to kill a process on an endpoint"""
    try:
        # Simulate remote command execution via local PowerShell (for demo)
        cmd = f"Stop-Process -Id {pid} -Force"
        result = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True)
        
        status = "success" if result.returncode == 0 else "failed"
        details = f"Process {pid} killed" if status == "success" else f"Fail: {result.stderr}"
        
        crud.create_activity_log(db, schemas.ActivityLogCreate(
            action="kill_process",
            details={"pid": pid, "status": status, "id": endpoint_id}
        ), user_id=current_user.id)
        
        if status == "failed":
             return {"message": f"Command sent, but process {pid} was not found or already terminated.", "status": "simulated"}
            
        return {"message": details, "status": "success"}
    except Exception as e:
        print(f"Kill Process Error: {e}")
        return {"message": str(e), "status": "error"}

@router.post("/{endpoint_id}/kill-process/{pid}")
async def kill_process(endpoint_id: int, pid: int, db: Session = Depends(database.get_db),
                 current_user: models.User = Depends(auth.get_current_admin_user)):
    """Kill a process on an endpoint (Admin only) using PowerShell"""
    result = await kill_process_logic(endpoint_id, pid, db, current_user)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result["message"])
    return result

@router.post("/{endpoint_id}/telemetry")
def update_telemetry(endpoint_id: int, telemetry: schemas.SystemInfoCreate, db: Session = Depends(database.get_db)):
    # This endpoint should be protected by Agent Token, skipping auth for now for simplicity
    return crud.update_system_info(db, endpoint_id, telemetry)

@router.post("/{endpoint_id}/restart")
def restart_endpoint(endpoint_id: int, db: Session = Depends(database.get_db),
                     current_user: models.User = Depends(auth.get_current_active_user)):
    """Send restart command to endpoint"""
    endpoint = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    return {"message": f"Restart command sent to {endpoint.hostname}", "status": "pending"}

from fastapi.responses import FileResponse
import os

@router.get("/download-agent")
def download_agent(current_user: models.User = Depends(auth.get_current_active_user)):
    """Serve the Agent Installer .exe"""
    # Use absolute path relative to this file to be safe
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # app/
    file_path = os.path.join(base_dir, "static", "installers", "DefaultRemoteOffice_Agent.exe")
    
    if not os.path.exists(file_path):
        print(f"File not found at: {file_path}") # Debug log
        raise HTTPException(status_code=404, detail="Installer not found on server")
    
    return FileResponse(path=file_path, filename="DefaultRemoteOffice_Agent.exe", media_type='application/octet-stream')
