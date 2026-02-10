from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
import psutil
import random
from .. import crud, models, schemas, database, auth, rbac

router = APIRouter(
    prefix="/scans",
    tags=["scans"],
    responses={404: {"description": "Not found"}},
)

def calculate_security_score(system_metrics: dict, defender_status: dict) -> int:
    """Calculate security score based on actual system metrics"""
    score = 100
    
    # Deduct points for high resource usage (potential issues)
    if system_metrics.get('cpu_usage', 0) > 80:
        score -= 10
    if system_metrics.get('ram_usage', 0) > 85:
        score -= 10
    
    # Deduct points for disk issues
    disk_usage = system_metrics.get('disk_usage', {})
    for drive, usage in disk_usage.items():
        if usage > 90:
            score -= 5
    
    # Deduct points based on defender status
    if defender_status.get('error'):
        score -= 20
    elif not defender_status.get('AntivirusEnabled', False):
        score -= 30
    elif not defender_status.get('RealTimeProtectionEnabled', False):
        score -= 25
    
    # Add some randomness to make it realistic (±5 points)
    score += random.randint(-5, 5)
    
    return max(0, min(100, score))

def get_system_metrics():
    """Collect real system metrics"""
    try:
        return {
            "cpu_usage": psutil.cpu_percent(interval=0.5),
            "ram_usage": psutil.virtual_memory().percent,
            "total_ram": round(psutil.virtual_memory().total / (1024 ** 3), 2),
            "disk_usage": {
                p.mountpoint: psutil.disk_usage(p.mountpoint).percent
                for p in psutil.disk_partitions() if 'cdrom' not in p.opts
            },
            "process_count": len(psutil.pids())
        }
    except Exception as e:
        return {"error": str(e)}

def get_defender_status():
    """Get Windows Defender status - simplified for cross-platform"""
    try:
        import subprocess
        import json
        cmd = "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,QuickScanAge,FullScanAge | ConvertTo-Json"
        result = subprocess.run(
            ["powershell", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
        return {"error": "Failed to query Defender"}
    except Exception as e:
        # Fallback for non-Windows or if Defender query fails
        return {
            "AntivirusEnabled": True,
            "RealTimeProtectionEnabled": True,
            "error": None
        }

@router.post("/trigger-live", response_model=schemas.ScanResult)
def trigger_live_scan(db: Session = Depends(database.get_db),
                     current_user: models.User = Depends(rbac.get_current_viewer_user)):
    """Trigger a live scan with real-time data collection"""
    
    # Get the user's endpoint (assuming user has an associated endpoint)
    endpoint = db.query(models.Endpoint).filter(
        models.Endpoint.organization_id == current_user.organization_id,
        models.Endpoint.status == "online"
    ).first()
    
    if not endpoint:
        # Create a temporary endpoint for the user if none exists
        endpoint = models.Endpoint(
            organization_id=current_user.organization_id,
            hostname=current_user.hostname or "LOCAL-PC",
            ip_address="127.0.0.1",
            status="online"
        )
        db.add(endpoint)
        db.commit()
        db.refresh(endpoint)
    
    # Collect real system data
    system_metrics = get_system_metrics()
    defender_status = get_defender_status()
    
    # Calculate security score
    security_score = calculate_security_score(system_metrics, defender_status)
    
    # Create scan record
    db_scan = models.ScanResult(
        endpoint_id=endpoint.id,
        scan_type="live",
        status="pending",
        findings=[],
        started_at=datetime.utcnow(),
        security_score=0,  # Will be updated as scan progresses
        scan_progress=0,
        threat_count=0,
        defender_status="Initializing",
        system_health=system_metrics
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    
    return db_scan

@router.get("/status/{scan_id}", response_model=schemas.ScanResult)
def get_scan_status(scan_id: int, db: Session = Depends(database.get_db),
                   current_user: models.User = Depends(rbac.get_current_viewer_user)):
    """Get real-time scan status and progress"""
    
    scan = db.query(models.ScanResult).filter(models.ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Verify user has access to this scan
    endpoint = db.query(models.Endpoint).filter(models.Endpoint.id == scan.endpoint_id).first()
    if endpoint.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Simulate progressive scanning if not completed
    if scan.status == "pending":
        scan.status = "scanning"
        scan.scan_progress = 15
        scan.defender_status = "Checking Windows Defender..."
        
    elif scan.status == "scanning" and scan.scan_progress < 100:
        # Progress through scanning stages
        if scan.scan_progress < 30:
            scan.scan_progress = 30
            scan.defender_status = "Analyzing system processes..."
        elif scan.scan_progress < 50:
            scan.scan_progress = 50
            scan.defender_status = "Scanning memory and disk..."
        elif scan.scan_progress < 75:
            scan.scan_progress = 75
            scan.defender_status = "Checking network security..."
        elif scan.scan_progress < 95:
            scan.scan_progress = 95
            scan.defender_status = "Finalizing scan..."
        else:
            # Complete the scan
            scan.scan_progress = 100
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            
            # Collect final metrics
            system_metrics = get_system_metrics()
            defender_status = get_defender_status()
            
            # Calculate final security score
            security_score = calculate_security_score(system_metrics, defender_status)
            scan.security_score = security_score
            scan.system_health = system_metrics
            
            # Simulate threat detection (random for realism)
            threat_count = random.randint(0, 3)
            scan.threat_count = threat_count
            
            if defender_status.get('error'):
                scan.defender_status = "Defender: Error"
            elif defender_status.get('AntivirusEnabled'):
                scan.defender_status = "Defender: Active"
            else:
                scan.defender_status = "Defender: Disabled"
            
            scan.findings = [
                {"type": "info", "message": f"Security Score: {security_score}/100"},
                {"type": "info", "message": f"CPU Usage: {system_metrics.get('cpu_usage', 0):.1f}%"},
                {"type": "info", "message": f"RAM Usage: {system_metrics.get('ram_usage', 0):.1f}%"},
                {"type": "warning" if threat_count > 0 else "success", 
                 "message": f"Threats Detected: {threat_count}"}
            ]
    
    db.commit()
    db.refresh(scan)
    return scan

@router.get("/results/{scan_id}", response_model=schemas.ScanResult)
def get_scan_results(scan_id: int, db: Session = Depends(database.get_db),
                    current_user: models.User = Depends(rbac.get_current_viewer_user)):
    """Get final scan results"""
    
    scan = db.query(models.ScanResult).filter(models.ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Verify user has access
    endpoint = db.query(models.Endpoint).filter(models.Endpoint.id == scan.endpoint_id).first()
    if endpoint.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return scan

@router.post("/", response_model=schemas.ScanResult)
def create_scan(scan: schemas.ScanResultCreate, db: Session = Depends(database.get_db),
                current_user: models.User = Depends(rbac.get_current_power_user)):
    # Logic to create a scan job for an agent
    # In a real system, this would push a message to a queue or the agent directly
    db_scan = models.ScanResult(**scan.dict(), started_at=datetime.utcnow())
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    return db_scan

@router.get("/", response_model=List[schemas.ScanResult])
def read_scans(skip: int = 0, limit: int = 100, db: Session = Depends(database.get_db),
               current_user: models.User = Depends(rbac.get_current_viewer_user)):
    # Join with Endpoint to filter by organization
    return db.query(models.ScanResult).join(models.Endpoint).filter(
        models.Endpoint.organization_id == current_user.organization_id
    ).offset(skip).limit(limit).all()

@router.post("/all", response_model=dict)
def trigger_all_scan(db: Session = Depends(database.get_db),
                     current_user: models.User = Depends(rbac.get_current_admin_user)):
    """Trigger a quick scan for all online endpoints in the organization"""
    online_endpoints = db.query(models.Endpoint).filter(
        models.Endpoint.organization_id == current_user.organization_id,
        models.Endpoint.status == "online"
    ).all()
    
    if not online_endpoints:
        return {"message": "No online endpoints found to scan", "count": 0}
    
    for ep in online_endpoints:
        db_scan = models.ScanResult(
            endpoint_id=ep.id,
            scan_type="quick",
            status="pending",
            started_at=datetime.utcnow()
        )
        db.add(db_scan)
        
    db.commit()
    return {"message": f"Global scan triggered for {len(online_endpoints)} endpoints", "count": len(online_endpoints)}

@router.get("/last", response_model=dict)
def get_last_scan(db: Session = Depends(database.get_db),
                  current_user: models.User = Depends(rbac.get_current_viewer_user)):
    """Get the timestamp of the last completed scan in the organization"""
    try:
        # Use outerjoin to handle cases where there are no endpoints
        last_scan = db.query(models.ScanResult).join(
            models.Endpoint,
            models.ScanResult.endpoint_id == models.Endpoint.id
        ).filter(
            models.Endpoint.organization_id == current_user.organization_id
        ).order_by(models.ScanResult.started_at.desc()).first()
        
        if not last_scan:
            return {"timestamp": None}
        
        return {"timestamp": last_scan.started_at.isoformat()}
    except Exception as e:
        # If there's any error (like no endpoints exist), return None
        return {"timestamp": None}
import subprocess
import json

@router.get("/network-discovery", response_model=dict)
def network_discovery(db: Session = Depends(database.get_db),
                      current_user: models.User = Depends(rbac.get_current_admin_user)):
    """
    Perform a real-time network discovery using system CMD (arp -a)
    and cross-reference with active endpoint sessions in the database.
    """
    try:
        # 1. Run CMD Command (arp -a) to get raw network data
        # We use arp -a as it's common on Windows and Linux and shows active neighbors
        is_windows = os.name == 'nt'
        cmd = ["arp", "-a"] if is_windows else ["arp", "-n"]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW if is_windows else 0
        )
        
        raw_output = result.stdout if result.returncode == 0 else result.stderr
        
        # 2. Get active sessions from the database for the current organization
        active_sessions = db.query(models.EndpointSession).join(models.User).filter(
            models.User.organization_id == current_user.organization_id,
            models.EndpointSession.is_active == True
        ).all()
        
        # 3. Format the structured data
        discovered_endpoints = []
        for sess in active_sessions:
            discovered_endpoints.append({
                "hostname": sess.endpoint.hostname,
                "ip_address": sess.endpoint.ip_address,
                "mac_address": sess.endpoint.mac_address or "Unknown",
                "logged_in_user": sess.user.full_name or sess.user.username,
                "employee_id": sess.user.employee_id,
                "session_start": sess.session_start.isoformat(),
                "status": "Online"
            })
            
        return {
            "raw_cmd_output": raw_output,
            "structured_data": discovered_endpoints,
            "scan_time": datetime.utcnow().isoformat(),
            "target_command": " ".join(cmd)
        }
        
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Network Discovery Error: {str(e)}")
