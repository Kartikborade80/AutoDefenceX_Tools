import subprocess
import platform
import logging
import os

# Configure logging to file
log_file = os.path.join(os.getcwd(), "enforcer_debug.log")
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def run_powershell(cmd: str):
    """Executes a PowerShell command and returns success status."""
    if platform.system() != "Windows":
        logging.warning(f"Attempted to run Windows command on {platform.system()}: {cmd}")
        return False
    
    try:
        # Use -Command to execute the script block
        result = subprocess.run(
            ["powershell", "-Command", cmd],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode != 0:
            logging.error(f"PowerShell Command Failed: {cmd}\nError: {result.stderr}")
            return False
        return True
    except Exception as e:
        logging.error(f"Failed to execute PowerShell: {str(e)}")
        return False

def enforce_policy(policy_type: str, enabled: bool):
    """Maps a policy type to a specific Windows system command."""
    
    # Policy commands mapping (PowerShell)
    commands = {
        "usb_lock": {
            True: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name "Start" -Value 4',
            False: 'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" -Name "Start" -Value 3'
        },
        "wallpaper_lock": {
            True: 'New-Item -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop" -Force; Set-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop" -Name "NoChangingWallPaper" -Value 1',
            False: 'Remove-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop" -Name "NoChangingWallPaper" -ErrorAction SilentlyContinue'
        },
        "firewall": {
            True: 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True',
            False: 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False'
        },
        "auto_update": {
            True: 'Set-Service wuauserv -StartupType Automatic; Start-Service wuauserv',
            False: 'Stop-Service wuauserv; Set-Service wuauserv -StartupType Disabled'
        },
        "screen_lock": {
            True: 'Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "ScreenSaveActive" -Value 1',
            False: 'Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "ScreenSaveActive" -Value 0'
        },
        "password_policy": {
            True: 'net accounts /minpwlen:12',
            False: 'net accounts /minpwlen:8'
        },
        "camera_lock": {
            True: 'Disable-PnpDevice -InstanceId (Get-PnpDevice -FriendlyName "*Camera*").InstanceId -Confirm:$false',
            False: 'Enable-PnpDevice -InstanceId (Get-PnpDevice -FriendlyName "*Camera*").InstanceId -Confirm:$false'
        },
        "microphone_lock": {
            True: 'Get-AudioDevice -List | Where-Object { $_.Type -eq "Recording" } | ForEach-Object { Disable-PnpDevice -InstanceId $_.ID -Confirm:$false }',
            False: 'Get-AudioDevice -List | Where-Object { $_.Type -eq "Recording" } | ForEach-Object { Enable-PnpDevice -InstanceId $_.ID -Confirm:$false }'
        }
    }

    if policy_type in commands:
        cmd = commands[policy_type].get(enabled)
        if cmd:
            logging.info(f"Enforcing policy '{policy_type}' (Enabled: {enabled})")
            return run_powershell(cmd)
    
    return False

def sync_policies(policies_db):
    """Takes a list of policy objects from DB and enforces them all."""
    status = {}
    for policy in policies_db:
        success = enforce_policy(policy.policy_type, policy.enabled)
        status[policy.policy_type] = success
    return status
