from sqlalchemy.orm import Session
from . import crud, models, schemas, database, auth
import sys

def init_db():
    # Ensure tables are created
    models.Base.metadata.create_all(bind=database.engine)
    
    db = next(database.get_db())
    
    # Check if admin already exists
    admin = db.query(models.User).filter(models.User.username == "admin").first()
    if not admin:
        print("Creating default admin user...")
        admin_in = schemas.AdminRegisterCreate(
            username="admin",
            password="admin123",
            full_name="System Administrator",
            email="admin@autodefencex.com",
            company_name="AutoDefenceX Security",
            company_address="Security Plaza, Cyber City",
            phone="+1234567890"
        )
        crud.create_admin_user(db, admin_in)
        print("Default admin created successfully (admin/admin123)")
    else:
        print("Admin user already exists.")

if __name__ == "__main__":
    init_db()
