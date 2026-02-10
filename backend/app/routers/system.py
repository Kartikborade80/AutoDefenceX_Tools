from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from ..auth import get_current_user
from .. import models
import platform
import psutil
import json

router = APIRouter(prefix="/system", tags=["system"])

def run_powershell(cmd):
    if platform.system() != "Windows":
        return None
    try:
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

@router.get("/info")
def get_system_info(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # 1. Try to fetch from DB (Agent Report)
    # Get last updated endpoint for this user?
    # or get the endpoint that matches the user's primary device.
    # We will search for ANY online endpoint for this user's organization that matches their assigned hostname, 
    # or just the most recently updated one.
    
    endpoint = db.query(models.Endpoint).filter(
        models.Endpoint.organization_id == current_user.organization_id
        # In a real scenario, we'd filter by current_user.device_id or similar
    ).order_by(models.Endpoint.last_seen.desc()).first()
    
    if endpoint and endpoint.system_info:
        try:
            sys_info = endpoint.system_info
            
            # Parse OS details from endpoint.os_details (JSON string)
            os_data = json.loads(endpoint.os_details) if endpoint.os_details else {}
            if not os_data: 
                # Fallback if empty
                os_data = {
                    "name": endpoint.os_details or "Windows (Agent)",
                    "version": "Unknown",
                    "arch": "Unknown" 
                }
            
            # Retrieve CPU info stashed in running_processes
            cpu_info = sys_info.running_processes.get("_cpu_info", {}) if sys_info.running_processes else {}
            
            # Construct Response
            return {
                "hostname": endpoint.hostname,
                "os": os_data,
                "cpu": {
                    "name": cpu_info.get("name", "Unknown Processor"),
                    "cores": cpu_info.get("cores", "Unknown"),
                    "logical": cpu_info.get("logical", 0)
                },
                "ram": {
                    "total_gb": sys_info.total_ram,
                    "free_gb": round(sys_info.total_ram * (1 - (sys_info.ram_usage/100)), 2),
                    "used_gb": round(sys_info.total_ram * (sys_info.ram_usage/100), 2),
                    "percent_used": sys_info.ram_usage
                }
            }
        except Exception as e:
            logging.error(f"Error serving agent details: {e}")
            # Fallthrough to local server info


    # 2. Linux / Non-Windows Support (Render/Docker) server fallback
    if platform.system() != "Windows":
        try:
            mem = psutil.virtual_memory()
            total_gb = round(mem.total / (1024**3), 2)
            free_gb = round(mem.available / (1024**3), 2)
            
            return {
                "hostname": platform.node(),
                "os": {
                    "name": f"{platform.system()} {platform.release()}",
                    "version": platform.version(),
                    "arch": platform.machine()
                },
                "cpu": {
                    "name": f"{platform.processor()} ({psutil.cpu_count()} cores)",
                    "cores": psutil.cpu_count(logical=False) or 1,
                    "logical": psutil.cpu_count(logical=True) or 1
                },
                "ram": {
                    "total_gb": total_gb,
                    "free_gb": free_gb,
                    "used_gb": round(total_gb - free_gb, 2),
                    "percent_used": mem.percent
                }
            }
        except Exception as e:
             return {"error": f"Failed to fetch Linux system info: {str(e)}"}

    # Fetch Basic Info
    # CsName = Hostname, OsName = OS, WindowsVersion = Build
    cmd_basic = "Get-ComputerInfo | Select-Object -Property CsName, OsName, WindowsVersion, OsArchitecture, CsProcessors, CsTotalPhysicalMemory"
    data = run_powershell(cmd_basic)

    # Fetch CPU detailed (Get-ComputerInfo's CsProcessors can be complex object)
    # WMI often cleaner for simple "Name"
    cmd_cpu = "Get-CimInstance Win32_Processor | Select-Object -Property Name, NumberOfCores, NumberOfLogicalProcessors"
    cpu_data = run_powershell(cmd_cpu)

    # Fetch RAM Free
    cmd_ram = "Get-CimInstance Win32_OperatingSystem | Select-Object -Property FreePhysicalMemory, TotalVisibleMemorySize"
    ram_data = run_powershell(cmd_ram)

    if not data:
        return {"error": "Failed to fetch system info"}

    # Handle lists vs objects
    if isinstance(data, list): data = data[0]
    if isinstance(cpu_data, list): cpu_data = cpu_data[0]
    if isinstance(ram_data, list): ram_data = ram_data[0]

    # Parsing / Formatting
    total_ram_gb = round(int(data.get("CsTotalPhysicalMemory", 0)) / (1024**3), 2)
    free_ram_gb = round(int(ram_data.get("FreePhysicalMemory", 0)) / (1024*1024), 2) # FreePhysicalMemory is in KB usually from CIM
    # Wait, Win32_OperatingSystem FreePhysicalMemory is in KB. 
    # Let's double check. Yes KB.
    # TotalVisible is also KB.
    # CsTotalPhysicalMemory from Get-ComputerInfo is Bytes.
    
    # Recalculate Free from CIM to be safe
    free_ram_gb = round(int(ram_data.get("FreePhysicalMemory", 0)) / 1024 / 1024, 2)

    return {
        "hostname": data.get("CsName", "Unknown"),
        "os": {
            "name": data.get("OsName", "Windows"),
            "version": data.get("WindowsVersion", "Unknown"),
            "arch": data.get("OsArchitecture", "Unknown")
        },
        "cpu": {
            "name": cpu_data.get("Name", "Unknown Processor"),
            "cores": cpu_data.get("NumberOfCores", 0),
            "logical": cpu_data.get("NumberOfLogicalProcessors", 0)
        },
        "ram": {
            "total_gb": total_ram_gb,
            "free_gb": free_ram_gb,
            "used_gb": round(total_ram_gb - free_ram_gb, 2),
            "percent_used": round(((total_ram_gb - free_ram_gb) / total_ram_gb) * 100, 1) if total_ram_gb > 0 else 0
        }
    }
