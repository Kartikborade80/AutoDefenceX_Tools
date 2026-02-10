import psutil
import time
from typing import List, Dict

class SwarmMonitor:
    def __init__(self):
        self.known_processes = set()
        self.update_process_list()

    def update_process_list(self):
        """Update the list of known PIDs."""
        self.known_processes = {p.pid for p in psutil.process_iter(['pid'])}

    def check_new_processes(self) -> List[Dict]:
        """Return details of any new processes started since last check."""
        current_pids = {p.pid for p in psutil.process_iter(['pid'])}
        new_pids = current_pids - self.known_processes
        
        new_process_details = []
        for pid in new_pids:
            try:
                p = psutil.Process(pid)
                new_process_details.append({
                    "pid": pid,
                    "name": p.name(),
                    "exe": p.exe(),
                    "create_time": p.create_time()
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        self.known_processes = current_pids
        return new_process_details

    def check_usb_devices(self) -> List[str]:
        """Check for connected removable drives."""
        # Simple check using psutil disk_partitions
        usb_drives = []
        try:
            partitions = psutil.disk_partitions(all=True)
            for p in partitions:
                if 'removable' in p.opts or 'cdrom' in p.opts or 'usb' in p.opts:
                     usb_drives.append(p.mountpoint)
        except Exception as e:
            print(f"Error checking USBs: {e}")
        return usb_drives
