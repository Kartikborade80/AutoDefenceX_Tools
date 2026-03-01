from app.database import SessionLocal
from app.models import User
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

db = SessionLocal()

username = "kartik.borade"
password = "Jondon@123456"

user = db.query(User).filter(User.username == username).first()

if user:
    print(f"User {username} exists. ID: {user.id}, Role: {user.role}")
    user.role = "admin" # Force admin role
    if pwd_context.verify(password, user.hashed_password):
        print("Password matches!")
    else:
        print("Password DOES NOT match. Updating password...")
        user.hashed_password = pwd_context.hash(password)
    db.commit()
    print("User updated successfully.")
else:
    print(f"User {username} DOES NOT exist. Creating...")
    new_user = User(
        username=username,
        hashed_password=pwd_context.hash(password),
        role="admin",
        full_name="Kartik Borade",
        is_normal_user=True,
        is_department_head=True,
        email="kartik.borade@autodefencex.com",
        must_change_password=False
    )
    db.add(new_user)
    db.commit()
    print("User created successfully.")

db.close()
