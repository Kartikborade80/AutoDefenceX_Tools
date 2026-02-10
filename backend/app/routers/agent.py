from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from ..database import get_db
from ..auth import get_current_user
from .. import models
import json
from datetime import datetime

router = APIRouter(prefix="/agent", tags=["agent"])

@router.post("/report")
def report_agent_data(
    data: dict, 
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    """
    Receives system info and defender status from the local agent script.
    Updates Endpoint, SystemInfo, and ScanResult tables.
    """
    
    sys_info = data.get("system_info", {})
    def_status = data.get("defender_status", {})
    
    hostname = sys_info.get("hostname", "Unknown")
    
    # 1. Find or Create Endpoint for this User
    # We assume 1-to-1 mapping for the simple agent: User -> Endpoint
    # Or match by hostname if existing?
    # Let's use the user's ID to find their primary endpoint or create one.
    
    endpoint = db.query(models.Endpoint).filter(
        models.Endpoint.hostname == hostname,
        models.Endpoint.organization_id == current_user.organization_id
    ).first()
    
    if not endpoint:
        # Check if user has an endpoint assigned (optional, but good for multi-device)
        # For now, create new
        endpoint = models.Endpoint(
            organization_id=current_user.organization_id,
            hostname=hostname,
            ip_address=None, # Agent could send this too
            status="online",
            trust_score=100
        )
        db.add(endpoint)
        db.commit()
        db.refresh(endpoint)
        
    # Update Endpoint Basic Info
    endpoint.last_seen = datetime.utcnow()
    endpoint.status = "online"
    
    # Store OS and Hardware details as JSON string in os_details
    # Merge keys if possible
    os_data = sys_info.get("os", {})
    hardware_data = sys_info.get("hardware", {})
    full_details = {**os_data, **hardware_data}
    
    endpoint.os_details = json.dumps(full_details)
    endpoint.trust_score = int(def_status.get("secure_score", "100/100").split("/")[0])
    
    # 2. Update System Info
    # SystemInfo table: cpu_usage, ram_usage, total_ram, disk_usage...
    
    system_info_record = db.query(models.SystemInfo).filter(
        models.SystemInfo.endpoint_id == endpoint.id
    ).first()
    
    ram_data = sys_info.get("ram", {})
    
    if not system_info_record:
        system_info_record = models.SystemInfo(
            endpoint_id=endpoint.id,
            cpu_usage=0.0, # Agent didn't send usage % yet, could add
            ram_usage=ram_data.get("percent_used", 0.0),
            total_ram=ram_data.get("total_gb", 0.0),
            disk_usage={}, # Agent TODO
            running_processes={}, # Store CPU Name here as hack key?
            installed_software={} 
        )
        db.add(system_info_record)
    else:
        system_info_record.ram_usage = ram_data.get("percent_used", 0.0)
        system_info_record.total_ram = ram_data.get("total_gb", 0.0)
        system_info_record.updated_at = datetime.utcnow()
        
    # Hack: Store CPU info in running_processes for retrieval by system.py
    # Since running_processes is JSON, we can add a special key
    cpu_info = sys_info.get("cpu", {})
    system_info_record.running_processes = {"_cpu_info": cpu_info}

    # 3. Update Scan Result / Defender Status
    # Store the FULL defender status JSON in ScanResult.defender_status (string) or system_health (JSON)
    # ScanResult.defender_status is String. system_health is JSON.
    # Let's use `system_health` to store the full defender JSON object.
    
    scan_result = db.query(models.ScanResult).filter(
        models.ScanResult.endpoint_id == endpoint.id
    ).order_by(models.ScanResult.started_at.desc()).first()
    
    if not scan_result:
        scan_result = models.ScanResult(
            endpoint_id=endpoint.id,
            scan_type="agent_report",
            status="completed",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )
        db.add(scan_result)
    
    scan_result.defender_status = def_status.get("health_status", "Unknown")
    scan_result.security_score = int(def_status.get("secure_score", "100/100").split("/")[0])
    scan_result.threat_count = def_status.get("scan_info", {}).get("threats_found", 0)
    
    # Critical: Store the full JSON so defender.py can serve it back exactly
    scan_result.system_health = def_status 
    
    db.commit()
    
    return {"status": "success", "message": "Data updated"}
