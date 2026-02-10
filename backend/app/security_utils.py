import re
import httpagentparser
from typing import Dict, Optional

def validate_password_strength(password: str) -> dict:
    """
    Validates a password against several criteria:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return {"valid": False, "message": "Password must be at least 8 characters long."}
    if not re.search(r"[A-Z]", password):
        return {"valid": False, "message": "Password must contain at least one uppercase letter."}
    if not re.search(r"[a-z]", password):
        return {"valid": False, "message": "Password must contain at least one lowercase letter."}
    if not re.search(r"\d", password):
        return {"valid": False, "message": "Password must contain at least one digit."}
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return {"valid": False, "message": "Password must contain at least one special character."}
    
    return {"valid": True, "message": "Password is strong."}

def parse_user_agent(ua_string: str) -> Dict[str, Optional[str]]:
    """
    Parses a user agent string to extract granular OS and Browser info.
    """
    try:
        parsed = httpagentparser.detect(ua_string)
        return {
            "browser_name": parsed.get('browser', {}).get('name'),
            "browser_version": parsed.get('browser', {}).get('version'),
            "os_name": parsed.get('os', {}).get('name'),
            "os_version": parsed.get('os', {}).get('version')
        }
    except Exception as e:
        print(f"Error parsing User-Agent: {e}")
        return {
            "browser_name": None,
            "browser_version": None,
            "os_name": None,
            "os_version": None
        }
