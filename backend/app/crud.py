from sqlalchemy.orm import Session
from . import models, schemas
from passlib.context import CryptContext
from datetime import datetime
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_user(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def get_users(db: Session, organization_id: int = None, skip: int = 0, limit: int = 100):
    query = db.query(models.User)
    if organization_id:
        query = query.filter(models.User.organization_id == organization_id)
    return query.offset(skip).limit(limit).all()

def authenticate_user(db: Session, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not pwd_context.verify(password, user.hashed_password):
        return False
    return user

def create_user(db: Session, user: schemas.UserCreate, organization_id: int = None):
    import random
    import string
    import re
    
    # Get organization domain for email generation
    domain = "autodefencex.com"
    if organization_id:
        org = db.query(models.Organization).filter(models.Organization.id == organization_id).first()
        if org:
            domain = org.domain
    
    # Auto-generate employee_id if not provided
    if not user.employee_id:
        employee_id = f"EMP-{random.randint(10000, 99999)}"
        # Ensure uniqueness within organization
        while db.query(models.User).filter(
            models.User.employee_id == employee_id,
            models.User.organization_id == organization_id
        ).first():
            employee_id = f"EMP-{random.randint(10000, 99999)}"
    else:
        employee_id = user.employee_id
    
    # Auto-generate email if not provided (based on full_name and organization domain)
    if not user.email and user.full_name:
        # Generate email from full name: "John Doe" -> "john.doe@domain.com"
        name_parts = user.full_name.lower().strip().split()
        if len(name_parts) >= 2:
            email_prefix = f"{name_parts[0]}.{name_parts[-1]}"
        else:
            email_prefix = name_parts[0] if name_parts else user.username
        
        # Clean email prefix (remove special chars)
        email_prefix = re.sub(r'[^a-z0-9.]', '', email_prefix)
        email = f"{email_prefix}@{domain}"
    else:
        email = user.email or f"{user.username}@{domain}"
    
    # Auto-generate asset_id if not provided (based on job_title)
    if not user.asset_id and user.job_title:
        # Extract department from job title
        dept_map = {
            'engineer': 'ENG',
            'developer': 'DEV',
            'manager': 'MGT',
            'director': 'DIR',
            'analyst': 'ANL',
            'hr': 'HR',
            'marketing': 'MKT',
            'finance': 'FIN',
            'sales': 'SAL',
            'it': 'IT'
        }
        
        dept_code = 'GEN'  # Default
        job_lower = user.job_title.lower()
        for key, code in dept_map.items():
            if key in job_lower:
                dept_code = code
                break
        
        asset_id = f"ASSET-{dept_code}-{random.randint(100, 999)}"
    else:
        asset_id = user.asset_id
    
    hashed_password = pwd_context.hash(user.password)
    db_user = models.User(
        organization_id=organization_id,
        username=user.username,
        hashed_password=hashed_password,
        role=user.role,
        is_active=True,
        full_name=user.full_name,
        mobile_number=user.mobile_number,
        employee_id=employee_id,
        email=email,
        asset_id=asset_id,
        job_title=user.job_title,
        designation_code=user.designation_code,
        account_type=user.account_type,
        device_id=user.device_id,
        os_type=user.os_type,
        hostname=user.hostname,
        access_expiry=user.access_expiry,
        password_expiry_days=user.password_expiry_days,
        force_password_change=user.force_password_change,
        created_by=user.created_by,
        department_id=user.department_id,
        access_control=user.access_control,
        is_normal_user=user.is_normal_user,
        is_department_head=user.is_department_head,
        risk_score=0.0
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user

def update_user(db: Session, user_id: int, user_update: schemas.UserUpdate):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if not db_user:
        return None
    
    update_data = user_update.dict(exclude_unset=True)
    
    # Handle password hashing if included
    if 'password' in update_data and update_data['password']:
        hashed_pwd = pwd_context.hash(update_data['password'])
        update_data['hashed_password'] = hashed_pwd
        del update_data['password']
    
    for key, value in update_data.items():
        setattr(db_user, key, value)
    
    db.commit()
    db.refresh(db_user)
    return db_user


def create_admin_user(db: Session, admin: schemas.AdminRegisterCreate):
    try:
        # First, create or get the organization
        org = db.query(models.Organization).filter(
            models.Organization.name == admin.company_name
        ).first()
        
        if not org:
            # Create new organization
            org = models.Organization(
                name=admin.company_name,
                domain=admin.company_domain,
                address=admin.company_address
            )
            db.add(org)
            db.commit()
            db.refresh(org)
        
        # Create admin user linked to organization
        hashed_password = pwd_context.hash(admin.password)
        db_user = models.User(
            organization_id=org.id,
            username=admin.username,
            hashed_password=hashed_password,
            role="admin",
            is_active=True,
            full_name=admin.full_name,
            email=admin.email,
            phone=admin.phone,
            is_normal_user=True,
            is_head_admin=True,  # First admin of organization is head admin
            risk_score=0.0
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        return db_user
    except Exception as e:
        import traceback
        with open("error_log.txt", "w") as f:
            f.write(traceback.format_exc())
        db.rollback()
        raise e

def create_public_user(db: Session, user: schemas.PublicUserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = models.User(
        username=user.username,
        hashed_password=hashed_password,
        role="user",
        is_active=True,
        full_name=user.full_name,
        mobile_number=user.mobile_number,
        is_normal_user=True,
        risk_score=0.0
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user

def update_last_login(db: Session, user_id: int):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        db_user.last_login = datetime.utcnow()
        db.commit()
        db.refresh(db_user)
    return db_user

def create_ticket(db: Session, ticket: schemas.TicketCreate, user_id: int):
    db_ticket = models.Ticket(**ticket.dict(), user_id=user_id)
    db.add(db_ticket)
    db.commit()
    db.refresh(db_ticket)
    return db_ticket

def get_tickets(db: Session, organization_id: int = None, user_id: int = None, skip: int = 0, limit: int = 100):
    query = db.query(models.Ticket)
    if organization_id:
        # Join with User to filter by organization
        query = query.join(models.User, models.Ticket.user_id == models.User.id).filter(
            models.User.organization_id == organization_id
        )
    if user_id:
         query = query.filter(models.Ticket.user_id == user_id)
    return query.offset(skip).limit(limit).all()

def create_activity_log(db: Session, activity: schemas.ActivityLogCreate, user_id: int):
    db_log = models.ActivityLog(**activity.dict(), user_id=user_id)
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    
    # Broadcast via WebSockets
    try:
        from .websockets import manager
        import asyncio
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if user and user.organization_id:
            asyncio.create_task(manager.broadcast_to_org(user.organization_id, {
                "type": "activity_log",
                "data": {
                    "id": db_log.id,
                    "action": db_log.action,
                    "details": db_log.details,
                    "timestamp": db_log.timestamp.isoformat(),
                    "username": user.username
                }
            }))
    except Exception as e:
        print(f"Broadcast error: {e}")
        
    return db_log

def get_activity_logs(db: Session, user_id: int, skip: int = 0, limit: int = 100):
     return db.query(models.ActivityLog).filter(models.ActivityLog.user_id == user_id).offset(skip).limit(limit).all()

def get_endpoints(db: Session, organization_id: int = None, skip: int = 0, limit: int = 100):
    query = db.query(models.Endpoint)
    if organization_id:
        query = query.filter(models.Endpoint.organization_id == organization_id)
    return query.offset(skip).limit(limit).all()

def get_endpoint_details(db: Session, endpoint_id: int):
    return db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()

def create_endpoint(db: Session, endpoint: schemas.EndpointCreate, organization_id: int = None):
    db_endpoint = models.Endpoint(
        organization_id=organization_id,
        hostname=endpoint.hostname,
        ip_address=endpoint.ip_address,
        mac_address=endpoint.mac_address,
        os_details=endpoint.os_details,
        status=endpoint.status,
        last_seen=datetime.utcnow()
    )
    db.add(db_endpoint)
    db.commit()
    db.refresh(db_endpoint)
    return db_endpoint

def update_system_info(db: Session, endpoint_id: int, info: schemas.SystemInfoCreate):
    # 1. Update Endpoint Last Seen
    endpoint = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    if endpoint:
        endpoint.last_seen = datetime.utcnow()
        endpoint.status = "online"
    
    # 2. Update System Info
    # Check if exists
    db_info = db.query(models.SystemInfo).filter(models.SystemInfo.endpoint_id == endpoint_id).first()
    if not db_info:
        db_info = models.SystemInfo(endpoint_id=endpoint_id, **info.dict())
        db.add(db_info)
    else:
        for key, value in info.dict().items():
            setattr(db_info, key, value)
        db_info.updated_at = datetime.utcnow()
    
    db.commit()
    return {"status": "success"}
