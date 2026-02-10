import psutil
import platform
import socket
import json
import uuid
from datetime import datetime

class SystemCollector:
    @staticmethod
    def get_basic_info():
        return {
            "hostname": socket.gethostname(),
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "mac_address": ":".join(["{:02x}".format((uuid >> ele) & 0xff)
                for uuid, ele in zip([uuid.getnode()], range(40, -8, -8))][::-1]),
            "os_details": f"{platform.system()} {platform.release()} {platform.version()}"
        }

    @staticmethod
    def get_resources():
        return {
            "cpu_usage": psutil.cpu_percent(interval=1),
            "ram_usage": psutil.virtual_memory().percent,
            "total_ram": round(psutil.virtual_memory().total / (1024 ** 3), 2),
            "disk_usage": {
                p.mountpoint: psutil.disk_usage(p.mountpoint).percent
                for p in psutil.disk_partitions() if 'cdrom' not in p.opts
            }
        }

    @staticmethod
    def get_installed_software():
        # Windows specific - using PowerShell via subprocess could be more accurate
        # but for python-only, this is limited.
        # We can implement a registry check here.
        # For MVP, we return a mock or basic list.
        return ["Chrome", "VSCode", "AutoDefenceX Agent"] 

    @staticmethod
    def get_running_processes(limit=10):
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'memory_percent']):
            try:
                procs.append(p.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Sort by memory usage
        procs.sort(key=lambda x: x['memory_percent'] or 0, reverse=True)
        return procs[:limit]
