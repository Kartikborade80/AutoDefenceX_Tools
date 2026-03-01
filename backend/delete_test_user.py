from app.database import SessionLocal
from app.models import User

def delete_user():
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == 'kartik.borade').first()
        if user:
            # Delete related data if any
            # (Assuming cleanup_admins.py logic or Cascades handle most things)
            db.delete(user)
            db.commit()
            print("User kartik.borade deleted successfully")
        else:
            print("User not found")
    except Exception as e:
        db.rollback()
        print(f"Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    delete_user()
