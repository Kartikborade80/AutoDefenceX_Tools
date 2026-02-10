from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import os
import sys
import shutil
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Check if DATABASE_URL is set (for production PostgreSQL)
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    # Production mode: Use DATABASE_URL from environment
    # Handle postgres:// vs postgresql:// for compatibility
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URL = DATABASE_URL
    connect_args = {}  # PostgreSQL doesn't need check_same_thread
else:
    # Local development or bundled app: Use SQLite
    # Determine the database location
    if getattr(sys, 'frozen', False):
        # Running as a bundled executable
        app_data_dir = os.path.join(os.environ.get('LOCALAPPDATA', os.getcwd()), "AutoDefenceX")
        if not os.path.exists(app_data_dir):
            os.makedirs(app_data_dir, exist_ok=True)
        
        db_path = os.path.join(app_data_dir, "autodefencex_v2.db")
        
        # SEEDING LOGIC: Move data if it's not there yet
        # OR if it's a fresh install (we can check if the file is newly created/empty)
        if not os.path.exists(db_path) or os.path.getsize(db_path) < 100 * 1024: # Less than 100KB is likely empty
            source_db = os.path.join(sys._MEIPASS, "autodefencex_v2.db") if hasattr(sys, '_MEIPASS') else None
            if source_db and os.path.exists(source_db):
                try:
                    # Close any existing connections (though there shouldn't be any yet)
                    shutil.copy2(source_db, db_path)
                    print(f"DEBUG: Seeded database to {db_path}")
                except Exception as e:
                    print(f"DEBUG: Failed to seed database: {e}")
    else:
        # Development mode
        db_path = "./autodefencex_v2.db"
    
    SQLALCHEMY_DATABASE_URL = f"sqlite:///{db_path}"
    connect_args = {"check_same_thread": False}  # SQLite needs this

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args=connect_args
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
