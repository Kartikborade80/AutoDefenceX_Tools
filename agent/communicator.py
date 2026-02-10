import requests
from .config import config

class Communicator:
    def __init__(self):
        self.base_url = config.SERVER_URL
        self.token = None 

    def register(self, payload):
        try:
            url = f"{self.base_url}/endpoints/"
            resp = requests.post(url, json=payload)
            if resp.status_code in [200, 201]:
                return resp.json()
            else:
                return None # Registration likely failed or already exists
        except Exception:
            return None

    def send_telemetry(self, endpoint_id, system_info):
        """Send full system info packet to backend."""
        try:
            url = f"{self.base_url}/endpoints/{endpoint_id}/telemetry"
            # In a real scenario, attach headers={"Authorization": f"Bearer {self.token}"}
            resp = requests.post(url, json=system_info)
            return resp.status_code == 200
        except Exception as e:
            print(f"[!] Telemetry upload failed: {e}")
            return False
