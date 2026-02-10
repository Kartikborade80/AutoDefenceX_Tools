from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
import sys
import os

# Ensure we can import from app
sys.path.append(os.getcwd())

from app.models import User
from app.database import Base, engine, SessionLocal

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def reset_password(username, new_password):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if user:
            print(f"Found user: {username}")
            user.hashed_password = pwd_context.hash(new_password)
            db.commit()
            print(f"✅ Password for '{username}' has been successfully reset to '{new_password}'")
        else:
            print(f"❌ User '{username}' not found!")
    except Exception as e:
        print(f"Error resetting password: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    # Resetting password for 'kartik.borade' to 'Pass@123'
    reset_password("kartik.borade", "Pass@123")
