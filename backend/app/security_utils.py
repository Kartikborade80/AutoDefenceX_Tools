import re
import httpagentparser
from typing import Dict, Optional

# Common passwords to block (top 100 most common)
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567", 
    "letmein", "trustno1", "dragon", "baseball", "111111", "iloveyou", "master",
    "sunshine", "ashley", "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "welcome", "jesus", "ninja",
    "mustang", "password1", "123456789", "adobe123", "admin", "1234567890",
    "photoshop", "1234", "12345", "password123", "welcome123", "admin123",
    "root", "toor", "pass", "test", "guest", "oracle", "changeme", "password1!",
    "qwerty123", "temp", "temppass", "default", "user", "demo", "sample",
    # Default passwords that must be blocked
    "pass@123", "pass123", "pass@1234", "password@123"
}

def validate_password_strength(password: str, user_full_name: str = None, username: str = None) -> dict:
    """
    Enhanced password validation with strict security requirements:
    - Minimum 12 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    - No common passwords
    - No sequential characters (123, abc)
    - No repeated characters (aaa, 111)
    - Cannot contain user's first name or last name
    - Cannot contain username
    """
    # Check minimum length
    if len(password) < 12:
        return {"valid": False, "message": "Password must be at least 12 characters long."}
    
    # Check for uppercase
    if not re.search(r"[A-Z]", password):
        return {"valid": False, "message": "Password must contain at least one uppercase letter."}
    
    # Check for lowercase
    if not re.search(r"[a-z]", password):
        return {"valid": False, "message": "Password must contain at least one lowercase letter."}
    
    # Check for digit
    if not re.search(r"\d", password):
        return {"valid": False, "message": "Password must contain at least one digit."}
    
    # Check for special character
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return {"valid": False, "message": "Password must contain at least one special character."}
    
    # Check against common passwords (case-insensitive)
    if password.lower() in COMMON_PASSWORDS:
        return {"valid": False, "message": "This password is too common. Please choose a more unique password."}
    
    # Check if password contains username
    if username and len(username) >= 3:
        if username.lower() in password.lower():
            return {"valid": False, "message": "Password cannot contain your username."}
    
    # Check if password contains first name or last name
    if user_full_name:
        # Split full name into parts
        name_parts = user_full_name.strip().split()
        for name_part in name_parts:
            if len(name_part) >= 3:  # Only check names with 3+ characters
                if name_part.lower() in password.lower():
                    return {"valid": False, "message": "Password cannot contain your first name or last name."}
    
    # Check for sequential characters (numbers)
    for i in range(len(password) - 2):
        if password[i:i+3].isdigit():
            num_seq = int(password[i:i+3])
            if num_seq == int(password[i]) * 111 or \
               (num_seq == int(password[i]) * 100 + int(password[i]) * 10 + int(password[i]) + 11):
                return {"valid": False, "message": "Password cannot contain sequential numbers (e.g., 123, 456)."}
    
    # Check for sequential characters (letters)
    for i in range(len(password) - 2):
        if password[i:i+3].isalpha():
            chars = password[i:i+3].lower()
            if ord(chars[1]) == ord(chars[0]) + 1 and ord(chars[2]) == ord(chars[1]) + 1:
                return {"valid": False, "message": "Password cannot contain sequential letters (e.g., abc, xyz)."}
    
    # Check for repeated characters (3 or more in a row)
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            return {"valid": False, "message": "Password cannot contain repeated characters (e.g., aaa, 111)."}
    
    return {"valid": True, "message": "Password is strong and secure."}

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
