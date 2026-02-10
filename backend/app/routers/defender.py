from fastapi import APIRouter
import subprocess
import json
import logging

router = APIRouter(prefix="/defender", tags=["defender"])

def run_powershell(cmd):
    try:
        # -WindowStyle Hidden is good practice, -OutputFormat Text to avoid weird wrapping
        completed = subprocess.run(
            ["powershell", "-Command", f"{cmd} | ConvertTo-Json -Depth 2"],
            capture_output=True,
            text=True
        )
        if completed.returncode != 0:
            logging.error(f"PowerShell Error: {completed.stderr}")
            return None
        return json.loads(completed.stdout)
    except Exception as e:
        logging.error(f"Execution Error: {str(e)}")
        return None

import threading

# Global state for scanning
scan_lock = threading.Lock()
is_scanning = False

@router.get("/status")
def get_defender_status():
    global is_scanning
    # Fetch Computer Status
    cmd_status = "Get-MpComputerStatus | Select-Object -Property AntivirusSignatureVersion, RealTimeProtectionEnabled, AMServiceEnabled, ComputerState, QuickScanAge, FullScanAge, AntivirusEnabled, QuickScanEndTime, FullScanEndTime"
    data = run_powershell(cmd_status)
    
    # Fetch Preferences (Exclusions, etc)
    cmd_pref = "Get-MpPreference | Select-Object -Property ExclusionPath, DisableRealtimeMonitoring, DisableIOAVProtection"
    pref_data = run_powershell(cmd_pref)
    
    # Fetch Threats
    cmd_threats = "Get-MpThreat | Select-Object -Property ThreatName, SeverityID, ThreatID, Resources"
    threats_data = run_powershell(cmd_threats)
    
    threats_list = []
    if threats_data:
        if isinstance(threats_data, list):
            threats_list = threats_data
        else:
            threats_list = [threats_data]

    # Defaults
    if not data:
        return {
            "health_status": "Unknown (Error)",
            # ... (safe defaults)
            "modules": {"virus_threat": False, "firewall": False, "app_control": False},
            "scan_info": {"is_scanning": False, "last_scan": "Unknown", "threats_found": 0, "history": []},
            "preferences": {"exclusions": []}
        }

    if isinstance(data, list): data = data[0]
    if isinstance(pref_data, list): pref_data = pref_data[0]
    elif not pref_data: pref_data = {}

    # Map Health
    state_map = {0: "Healthy", 1: "At Risk"}
    health = state_map.get(data.get("ComputerState", 99), "Attention Needed")
    
    # Score
    score = 0
    if data.get("RealTimeProtectionEnabled"): score += 40
    if data.get("AMServiceEnabled"): score += 30
    if data.get("AntivirusEnabled"): score += 30

    # Format Date
    last_scan = data.get("QuickScanEndTime", "Never")
    
    # Exclusions
    exclusions = pref_data.get("ExclusionPath", [])
    if isinstance(exclusions, str): exclusions = [exclusions] # Normalize to list

    return {
        "health_status": health,
        "secure_score": f"{score}/100",
        "definition_version": data.get("AntivirusSignatureVersion", "Unknown"),
        "last_checked_formatted": "Live from OS",
        "modules": {
            "virus_threat": data.get("RealTimeProtectionEnabled", False),
            "firewall": True, 
            "app_control": data.get("AMServiceEnabled", False)
        },
        "scan_info": {
            "is_scanning": is_scanning,
            "last_scan": str(last_scan),
            "threats_found": len(threats_list),
            "history": threats_list
        },
        "preferences": {
            "exclusions": exclusions,
            "realtime_monitor": not pref_data.get("DisableRealtimeMonitoring", False),
            "ioav_protection": not pref_data.get("DisableIOAVProtection", False)
        }
    }

@router.post("/scan")
def trigger_scan(scan_type: str = "quick"):
    global is_scanning
    if is_scanning:
        return {"status": "busy", "message": "Scan already in progress"}
    
    # Validate type
    ps_type = "QuickScan"
    if scan_type.lower() == "full":
        ps_type = "FullScan"
    
    def job():
        global is_scanning
        with scan_lock: is_scanning = True
        try:
            logging.info(f"Starting {ps_type}...")
            run_powershell(f"Start-MpScan -ScanType {ps_type}")
        except Exception as e:
            logging.error(f"Scan failed: {e}")
        finally:
            with scan_lock: is_scanning = False
            logging.info("Scan Finished")

    thread = threading.Thread(target=job)
    thread.start()
    
    return {"status": "started", "message": f"{ps_type} initiated in background"}

@router.post("/update")
def trigger_update():
    # Trigger real update
    # Note: This might require Admin privileges. 
    result = run_powershell("Update-MpSignature")
    
    # Re-fetch status to get new version
    status = run_powershell("Get-MpComputerStatus | Select-Object -Property AntivirusSignatureVersion")
    new_ver = status.get("AntivirusSignatureVersion") if status else "Unknown"

    return {
        "status": "updated", 
        "new_version": new_ver,
        "message": "Windows Defender signature update triggered."
    }
