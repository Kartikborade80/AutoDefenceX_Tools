from fastapi import APIRouter
import subprocess
import json
import logging

router = APIRouter(prefix="/system", tags=["system"])

def run_powershell(cmd):
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
def get_system_info():
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
