# AutoDefenceX - Project Runner
# This script starts both Backend and Frontend in separate windows

# 1. Cleanup existing processes
Write-Host "🛑 Cleaning up existing instances..." -ForegroundColor Yellow
Get-Process -Name uvicorn, python, node -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*AutodefeProject*" } | Stop-Process -Force
Start-Sleep -Seconds 1

# 2. Start Backend
Write-Host "🚀 Launching Backend API (Port 8000)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd backend; uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"

# 3. Start Frontend
Write-Host "✨ Launching Frontend Dashboard (Port 5178)..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd frontend; npx vite --port 5178"

Write-Host "`n✅ Both servers are initializing!" -ForegroundColor Green
Write-Host "Backend: http://localhost:8000"
Write-Host "Frontend: http://localhost:5178"
