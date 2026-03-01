import requests
import json
import sys

BASE_URL = "http://127.0.0.1:8000"

def log(msg):
    with open("test_api.log", "a", encoding="utf-8") as f:
        f.write(str(msg) + "\n")

def test_endpoints_api():
    # clear log file
    with open("test_api.log", "w", encoding="utf-8") as f:
        f.write("")

    log("Testing /endpoints/ API Routes")
    log("-" * 30)

    # 1. Login to get token
    log("1. Logging in to get token...")
    login_data = {"username": "kartik.borade", "password": "Jondon@123456"}
    res = requests.post(f"{BASE_URL}/auth/token", data=login_data)
    if res.status_code != 200:
        log(f"FAILED to login: {res.status_code} {res.text}")
        return
    
    token = res.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}
    log("Login successful.")

    # 2. Get all endpoints
    log("\n2. Getting all connected endpoints (GET /endpoints/)...")
    res = requests.get(f"{BASE_URL}/endpoints/", headers=headers)
    log(f"Status: {res.status_code}")
    if res.status_code == 200:
        endpoints = res.json()
        log(f"Returned {len(endpoints)} endpoints.")
        log(json.dumps(endpoints, indent=2))
    else:
        log(f"Response: {res.text}")

    # 3. Test download-agent (GET /endpoints/download-agent)
    log("\n3. Testing download-agent (GET /endpoints/download-agent)...")
    res_agent = requests.get(f"{BASE_URL}/endpoints/download-agent", headers=headers, stream=True)
    log(f"Status: {res_agent.status_code}")
    if res_agent.status_code == 200:
        log("Agent download works (file served).")
    elif res_agent.status_code == 404:
        log(f"Agent download not found: {res_agent.json()}")
    else:
        log(f"Unexpected status: {res_agent.text}")

    # 4. Try isolating a non-existent endpoint (should return 404)
    log("\n4. Testing isolate endpoint (POST /endpoints/9999/isolate)...")
    res_iso = requests.post(f"{BASE_URL}/endpoints/9999/isolate", headers=headers)
    log(f"Status: {res_iso.status_code}")
    log(f"Response: {res_iso.text}")

    # 5. Try to read a non-existent endpoint
    log("\n5. Testing read specific endpoint (GET /endpoints/9999)...")
    res_read = requests.get(f"{BASE_URL}/endpoints/9999", headers=headers)
    log(f"Status: {res_read.status_code}")
    log(f"Response: {res_read.text}")

if __name__ == '__main__':
    test_endpoints_api()
