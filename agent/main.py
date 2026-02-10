import time
import socket
from .config import config
from .collectors import SystemCollector
from .communicator import Communicator
from .monitor import SwarmMonitor
from .defender import DefenderUtils

class AutoDefenceAgent:
    def __init__(self):
        self.communicator = Communicator()
        self.endpoint_id = None
        self.monitor = None

    def enroll(self):
        """Register the endpoint with the server."""
        print(f"[*] Attempting to enroll...")
        basic_info = SystemCollector.get_basic_info()
        # Add required schema fields
        payload = {
            "hostname": basic_info["hostname"],
            "ip_address": basic_info["ip_address"],
            "mac_address": basic_info["mac_address"],
            "os_details": basic_info["os_details"],
            "status": "online"
        }
        
        result = self.communicator.register(payload)
        if result and 'id' in result:
            self.endpoint_id = result['id']
            print(f"[+] Enrolled with ID: {self.endpoint_id}")
        else:
            print("[!] Enrollment failed or already registered (assuming ID=1 for dev)")
            # For development, if we fail (e.g. 400 already exists), we might need logic to 'get' ID.
            # Here we just blindly assume we might be ID 1 if running locally single user.
            self.endpoint_id = 1 

    def run(self):
        print(f"[*] AutoDefenceX Agent Starting...")
        self.enroll()
        self.monitor = SwarmMonitor()
        
        while True:
            try:
                # 1. Collect Telemetry
                resources = SystemCollector.get_resources()
                software = SystemCollector.get_installed_software()
                processes = SystemCollector.get_running_processes()
                
                telemetry_payload = {
                    "cpu_usage": resources["cpu_usage"],
                    "ram_usage": resources["ram_usage"],
                    "total_ram": resources["total_ram"],
                    "disk_usage": resources["disk_usage"],
                    "running_processes": processes,
                    "installed_software": software
                }
                
                # 2. Send to Backend
                if self.endpoint_id:
                    self.communicator.send_telemetry(self.endpoint_id, telemetry_payload)
                    print(f"[*] Sent Heartbeat/Telemetry at {resources['cpu_usage']}% CPU")
                
                # 3. Local Monitoring (USB)
                usbs = self.monitor.check_usb_devices()
                if usbs:
                     print(f"[!] USB Detected: {usbs}")

            except Exception as e:
                print(f"[!] Agent Loop Error: {e}")

            time.sleep(10) # 10 seconds heartbeat

if __name__ == "__main__":
    agent = AutoDefenceAgent()
    agent.run()
