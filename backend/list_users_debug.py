from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import User
from app.database import Base

# Setup database connection
SQLALCHEMY_DATABASE_URL = "sqlite:///./autodefencex_v2.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def list_users():
    db = SessionLocal()
    try:
        users = db.query(User).limit(10).all()
        print(f"Found {len(users)} users (showing first 10):")
        for user in users:
            print(f"User: {user.username} | Role: {user.role}")
            if user.username == 'admin.dyp':
                print(f"--- FOUND TARGET USER: {user.username} ---")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    list_users()
