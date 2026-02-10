import requests
import logging

# In production, move to env vars
OTX_API_KEY = "15d85377f34e127121f112de43b5eb0e661fdf9173fb97a5767edc31a73f496d"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

class AlienVaultOTX:
    @staticmethod
    def get_indicator_details(indicator_type: str, indicator: str):
        """
        Check an indicator (IPv4, domain, file hash) against OTX.
        indicator_type: 'IPv4', 'domain', 'file'
        """
        headers = {'X-OTX-API-KEY': OTX_API_KEY}
        # OTX API uses 'file' for hashes (MD5, SHA1, SHA256)
        if indicator_type in ['md5', 'sha1', 'sha256']:
            indicator_type = 'file'
            
        url = f"{OTX_BASE_URL}/indicators/{indicator_type}/{indicator}/general"
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get("pulse_info", {})
                return {
                    "found": True,
                    "pulse_count": pulse_info.get("count", 0),
                    "references": [p.get("name") for p in pulse_info.get("pulses", [])[:3]], # Top 3 references
                    "malware_families": [m.get("name") for m in data.get("malware_families", [])]
                }
            elif response.status_code == 404:
                return {"found": False, "pulse_count": 0, "status": "Safe/Unknown"}
            else:
                logging.error(f"OTX API Error: {response.status_code}")
                return {"error": f"API Error {response.status_code}"}
        except Exception as e:
            logging.error(f"OTX Connection Error: {e}")
            return {"error": str(e)}
