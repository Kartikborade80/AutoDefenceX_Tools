from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
from dotenv import load_dotenv
from .routers import users, endpoints, scans, auth, threat_intel, reports, departments, policies, forensics, sessions, chatbot, otp, organizations, attendance, tasks, messages, defender, system, search, analytics, agent
from .websockets import manager
from .auth import get_current_user_from_token
from fastapi import WebSocket, WebSocketDisconnect, Query

# Load environment variables
load_dotenv()

from .database import engine, Base

# Create Database Tables
Base.metadata.create_all(bind=engine)

# Initialize Background Scheduler for Session Cleanup
from apscheduler.schedulers.background import BackgroundScheduler
from .tasks.session_cleanup import cleanup_inactive_sessions

scheduler = BackgroundScheduler()
scheduler.add_job(cleanup_inactive_sessions, 'interval', minutes=5, id='session_cleanup')
scheduler.start()

print("✅ Background Scheduler Started: Session cleanup running every 5 minutes")

app = FastAPI(
    title="AutoDefenceX API",
    description="Backend API for AutoDefenceX Cybersecurity Platform",
    version="0.3.0"
)

# CORS Configuration from environment
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*")
origins = ALLOWED_ORIGINS.split(",") if ALLOWED_ORIGINS != "*" else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi import Request
from fastapi.responses import JSONResponse
import traceback

@app.exception_handler(Exception)
async def debug_exception_handler(request: Request, exc: Exception):
    error_msg = "".join(traceback.format_exception(None, exc, exc.__traceback__))
    print(f"CRITICAL ERROR: {error_msg}") # Log to console for Render
    return JSONResponse(
        status_code=500,
        content={"message": "Internal Server Error", "detail": error_msg},
    )

# Activity Tracking Middleware
from .middleware.activity import update_last_activity
app.middleware("http")(update_last_activity)

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "AutoDefenceX-Core"}

@app.get("/debug/auth")
async def debug_auth():
    """Debug endpoint to check if auth dependencies are loaded correctly"""
    status = {"status": "ok", "details": {}}
    
    # Check Passlib/Bcrypt
    try:
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        hash = pwd_context.hash("test")
        status["details"]["bcrypt"] = "working"
    except Exception as e:
        status["status"] = "error"
        status["details"]["bcrypt"] = str(e)

    # Check JOSE
    try:
        import jose
        from jose import jwt
        status["details"]["jose"] = f"working (ver: {jose.__version__})"
    except Exception as e:
        status["status"] = "error"
        status["details"]["jose"] = str(e)
        
    # Check Requests
    try:
        import requests
        status["details"]["requests"] = f"working (ver: {requests.__version__})"
    except Exception as e:
        status["status"] = "error"
        status["details"]["requests"] = str(e)

    return status

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(endpoints.router)
app.include_router(scans.router)
app.include_router(analytics.router)
app.include_router(chatbot.router)
app.include_router(attendance.router)
app.include_router(reports.router)
app.include_router(tasks.router)
app.include_router(messages.router)
app.include_router(defender.router)
app.include_router(system.router)
app.include_router(search.router)
app.include_router(threat_intel.router)
app.include_router(departments.router)
app.include_router(policies.router)
app.include_router(forensics.router)
app.include_router(sessions.router)
app.include_router(otp.router)
app.include_router(organizations.router)
app.include_router(agent.router)

@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    try:
        from .database import SessionLocal
        db = SessionLocal()
        user = get_current_user_from_token(db, token)
        db.close()
        
        if not user:
            await websocket.close(code=1008)
            return

        org_id = user.organization_id
        await manager.connect(websocket, org_id)
        
        try:
            while True:
                # Keep connection alive, we primarily broadcast, but could receive commands
                data = await websocket.receive_text()
                # Handle incoming messages if needed
        except WebSocketDisconnect:
            manager.disconnect(websocket, org_id)
    except Exception as e:
        print(f"WebSocket error: {e}")
        try:
            await websocket.close()
        except:
            pass

# Serve Frontend static files
import sys
# Get the absolute path to the frontend/dist directory
if getattr(sys, 'frozen', False):
    # If running in a bundle, use _MEIPASS
    base_dir = sys._MEIPASS
    frontend_dist = os.path.join(base_dir, "frontend", "dist")
else:
    # Development mode
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    frontend_dist = os.path.join(base_dir, "frontend", "dist")

if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # If it's an API request, let it fall through to routers
        # (Though routers are already included, so they match first)
        
        # Check if the file exists in dist
        file_path = os.path.join(frontend_dist, full_path)
        if full_path and os.path.isfile(file_path):
            return FileResponse(file_path)
        
        # Otherwise return index.html for SPA routing
        return FileResponse(os.path.join(frontend_dist, "index.html"))
else:
    @app.get("/")
    async def root():
        return {"message": "AutoDefenceX Backend is Running - Static files not found"}


