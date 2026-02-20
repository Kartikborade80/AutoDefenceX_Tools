import requests

def get_location_from_ip(ip_address: str) -> str:
    """
    Retrieves the location (City, Country) for a given IP address.
    Returns 'Localhost' for local IPs or 'Unknown Location' on failure.
    """
    if ip_address in ["127.0.0.1", "::1", "localhost", "unknown"]:
        return "Localhost (Development)"
    
    try:
        # Using ip-api.com (free, no key required for basic usage)
        response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
        data = response.json()
        
        if data.get("status") == "success":
            city = data.get("city", "")
            country = data.get("country", "")
            return f"{city}, {country}"
        else:
            return "Unknown Location"
    except Exception as e:
        print(f"Geolocation Error: {e}")
        return "Unknown Location"
