"""
Backend Endpoint Testing Script
Tests login, heartbeat, and attendance endpoints
"""
import requests
import json
from datetime import datetime

print('=' * 50)
print('BACKEND ENDPOINT TESTING')
print('=' * 50)
print(f'\nTest Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')

# Test 1: Login
print('1. Testing Login Endpoint')
print('   Credentials: kartik.borade / Pass@123')
try:
    response = requests.post(
        'http://localhost:8000/auth/login',
        data={'username': 'kartik.borade', 'password': 'Pass@123'}
    )
    print(f'   Status: {response.status_code}')
    
    if response.status_code == 200:
        data = response.json()
        token = data.get('access_token')
        user_info = data.get('user_info', {})
        
        print('   ✅ Login successful')
        print(f'   User: {user_info.get("username")}')
        print(f'   Role: {user_info.get("role")}')
        print(f'   Department: {user_info.get("department_name")}')
        
        # Test 2: Heartbeat
        print('\n2. Testing Heartbeat Endpoint (with auth)')
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.post(
            'http://localhost:8000/attendance/heartbeat',
            headers=headers
        )
        print(f'   Status: {response.status_code}')
        
        if response.status_code == 200:
            heartbeat_data = response.json()
            print(f'   Response: {heartbeat_data}')
            print('   ✅ Heartbeat working correctly')
        else:
            print(f'   ❌ Heartbeat error: {response.text}')
        
        # Test 3: Attendance Records
        print('\n3. Testing Attendance Records')
        user_id = user_info.get('id')
        response = requests.get(
            f'http://localhost:8000/attendance/user/{user_id}',
            headers=headers
        )
        print(f'   Status: {response.status_code}')
        
        if response.status_code == 200:
            records = response.json()
            print(f'   Total records: {len(records)}')
            
            if records:
                latest = records[-1]
                print(f'   Latest login: {latest.get("login_time")}')
                print(f'   Session active: {latest.get("is_active")}')
                session_token = latest.get("session_token", "N/A")
                if session_token != "N/A":
                    print(f'   Session token: {session_token[:20]}...')
                print(f'   Last activity: {latest.get("last_activity")}')
                print('   ✅ Attendance tracking working')
            else:
                print('   ⚠️  No attendance records found')
        else:
            print(f'   ❌ Attendance error: {response.text}')
            
    else:
        print(f'   ❌ Login failed')
        print(f'   Response: {response.text}')
        
except Exception as e:
    print(f'   ❌ Error: {str(e)}')

print('\n' + '=' * 50)
print('TEST COMPLETE')
print('=' * 50)
