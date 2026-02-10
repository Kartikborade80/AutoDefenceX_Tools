import subprocess
import json
import logging

class DefenderUtils:
    @staticmethod
    def get_status():
        """
        Retrieve Windows Defender status using PowerShell.
        Returns a dict of status attributes.
        """
        cmd = "Get-MpComputerStatus | Select-Object * | ConvertTo-Json -Depth 1"
        try:
            # Run PowerShell command
            result = subprocess.run(
                ["powershell", "-Command", cmd],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode != 0:
                logging.error(f"Defender check failed: {result.stderr}")
                return {"error": "Failed to query Defender"}
                
            data = json.loads(result.stdout)
            return data
        except Exception as e:
            logging.error(f"Defender check exception: {e}")
            return {"error": str(e)}

    @staticmethod
    def trigger_scan(scan_type="QuickScan"):
        """
        Trigger a Defender scan.
        scan_type: QuickScan, FullScan
        """
        scan_param = 1 if scan_type == "QuickScan" else 2
        cmd = f"Start-MpScan -ScanType {scan_type}"
        try:
            subprocess.run(
                ["powershell", "-Command", cmd],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return True
        except Exception:
            return False
