from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Text, Float, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
import pytz
from .database import Base

# Indian Standard Time timezone
IST = pytz.timezone('Asia/Kolkata')

class Organization(Base):
    __tablename__ = "organizations"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)  # "INFO TECH PVT LTD"
    domain = Column(String, unique=True, index=True)  # "infotech.com"
    address = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    users = relationship("User", back_populates="organization")
    departments = relationship("Department", back_populates="organization")
    endpoints = relationship("Endpoint", back_populates="organization")
    policies = relationship("Policy", back_populates="organization")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String, default="viewer")  # 'admin', 'user', 'viewer'
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Organization Link (Multi-tenancy)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    
    # Expanded User Details
    full_name = Column(String, nullable=True)
    mobile_number = Column(String, nullable=True)
    mobile_verified = Column(Boolean, default=False)  # OTP verification status
    employee_id = Column(String, index=True, nullable=True)  # Removed unique constraint for multi-org
    asset_id = Column(String, nullable=True)
    job_title = Column(String, nullable=True)
    designation_code = Column(String, nullable=True) # Software Engineer, etc.
    account_type = Column(String, nullable=True) # Permanent, Contract, etc.
    email = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    mobile_number = Column(String, nullable=True)
    
    # Device & System
    device_id = Column(String, nullable=True)
    os_type = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    
    # Access Control & Expiry
    access_expiry = Column(DateTime, nullable=True)
    password_expiry_days = Column(Integer, default=90)
    force_password_change = Column(Boolean, default=False)
    created_by = Column(String, nullable=True) # Admin, HR Manager, etc.
    
    # Login Tracking
    last_login = Column(DateTime, nullable=True)
    
    # Security: Brute Force Protection
    failed_login_attempts = Column(Integer, default=0)
    account_locked_until = Column(DateTime, nullable=True)
    last_failed_login = Column(DateTime, nullable=True)
    
    # Security: Password Management
    must_change_password = Column(Boolean, default=False)
    password_changed_at = Column(DateTime, default=datetime.utcnow)
    
    # Access Control & Security
    risk_score = Column(Float, default=0.0)
    access_control = Column(JSON, default={}) # {"usb_block": False, "wallpaper_lock": False}
    is_normal_user = Column(Boolean, default=False) # True = Human User, False = Endpoint Agent
    
    # Dual Login Logic
    # If managed_by is set, this user belongs to an Admin's domain (Enrolled)
    managed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Department & Permissions
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=True)
    is_head_admin = Column(Boolean, default=False)  # Head Admin can manage all departments
    is_department_head = Column(Boolean, default=False)  # Department Head flag

    organization = relationship("Organization", back_populates="users")
    tickets = relationship("Ticket", back_populates="user", foreign_keys="[Ticket.user_id]")
    assigned_tickets = relationship("Ticket", back_populates="assigned_user", foreign_keys="[Ticket.assigned_to_user_id]")
    activities = relationship("ActivityLog", back_populates="user")
    department = relationship("Department", back_populates="users", foreign_keys=[department_id])
    applied_policies = relationship("Policy", back_populates="applied_to_user")
    forensic_logs = relationship("ForensicLog", back_populates="user")

class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String) # 'login', 'usb_inserted', 'suspicious_site'
    details = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="activities")

class IncidentReport(Base):
    __tablename__ = "incident_reports"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    type = Column(String)  # Phishing, Malware, Hardware, Other
    description = Column(Text)
    status = Column(String, default="open")  # open, investigating, resolved
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="incident_reports")

# Update User model to include relationship
User.incident_reports = relationship("IncidentReport", back_populates="user")

class Ticket(Base):
    __tablename__ = "tickets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))  # Creator of ticket
    assigned_to_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Assigned user
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=True)  # Target Department
    category = Column(String, nullable=True)  # Made optional since we're using assignment now
    description = Column(String)
    status = Column(String, default="open")  # 'open', 'in_progress', 'resolved', 'solved'
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="tickets", foreign_keys=[user_id])
    assigned_user = relationship("User", back_populates="assigned_tickets", foreign_keys=[assigned_to_user_id])
    department = relationship("Department")


class ThreatPattern(Base):
    __tablename__ = "threat_patterns"

    id = Column(Integer, primary_key=True, index=True)
    pattern_type = Column(String) # 'file_hash', 'ip', 'domain', 'process_name'
    value = Column(String, index=True, unique=True)
    description = Column(String)
    confidence_score = Column(Integer, default=0) # Increased by Swarm consensus or OTX
    source = Column(String) # 'OTX', 'Swarm', 'Manual'
    created_at = Column(DateTime, default=datetime.utcnow)

class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    hostname = Column(String, index=True)
    ip_address = Column(String)
    mac_address = Column(String, nullable=True)
    os_details = Column(String, nullable=True)
    status = Column(String, default="offline") # online, offline, isolated
    trust_score = Column(Integer, default=100)
    risk_level = Column(String, default="low") # low, medium, high, critical
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    organization = relationship("Organization", back_populates="endpoints")
    system_info = relationship("SystemInfo", back_populates="endpoint", uselist=False)
    scans = relationship("ScanResult", back_populates="endpoint")
    alerts = relationship("Alert", back_populates="endpoint")

class SystemInfo(Base):
    __tablename__ = "system_info"
    
    id = Column(Integer, primary_key=True, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"), unique=True)
    
    cpu_usage = Column(Float)
    ram_usage = Column(Float)
    total_ram = Column(Float) # GB
    disk_usage = Column(JSON) # {"C": "50%", "D": "20%"}
    running_processes = Column(JSON) # List of top resource consumers
    installed_software = Column(JSON) # List of installed apps
    
    updated_at = Column(DateTime, default=datetime.utcnow)

    endpoint = relationship("Endpoint", back_populates="system_info")

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"))
    
    scan_type = Column(String) # 'quick', 'full', 'usb', 'network'
    status = Column(String) # 'pending', 'scanning', 'completed', 'failed'
    findings = Column(JSON) # List of detected items
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    # Real-time scanning fields
    security_score = Column(Integer, default=0)  # Overall security rating 0-100
    scan_progress = Column(Integer, default=0)  # Current progress percentage
    threat_count = Column(Integer, default=0)  # Number of threats detected
    defender_status = Column(String, nullable=True)  # Windows Defender status
    system_health = Column(JSON, default={})  # Detailed system metrics

    endpoint = relationship("Endpoint", back_populates="scans")

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"))
    
    title = Column(String)
    description = Column(String)
    severity = Column(String) # low, medium, high, critical
    is_resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    endpoint = relationship("Endpoint", back_populates="alerts")

class ThreatIntel(Base):
    __tablename__ = "threat_intel"

    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String) # 'ip', 'domain', 'file_hash'
    value = Column(String, index=True)
    reputation = Column(String) # 'malicious', 'suspicious', 'safe'
    source = Column(String) # 'AlienVault', 'Internal'
    last_checked = Column(DateTime, default=datetime.utcnow)

class Department(Base):
    __tablename__ = "departments"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String, index=True)  # Removed unique constraint for multi-org
    description = Column(String, nullable=True)
    monitoring_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="departments")
    users = relationship("User", back_populates="department", foreign_keys="User.department_id")
    policies = relationship("Policy", back_populates="department")
    
    # HOD Link
    hod_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    hod = relationship("User", foreign_keys=[hod_id])

class Policy(Base):
    __tablename__ = "policies"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String, index=True)
    policy_type = Column(String)  # 'usb_block', 'wallpaper_lock', 'app_block', etc.
    enabled = Column(Boolean, default=False)
    config = Column(JSON, default={})  # Additional policy configuration
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=True)
    applied_to_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    organization = relationship("Organization", back_populates="policies")
    department = relationship("Department", back_populates="policies")
    applied_to_user = relationship("User", back_populates="applied_policies")

class ForensicLog(Base):
    __tablename__ = "forensic_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    event_type = Column(String)  # 'login', 'failed_login', 'logout', 'suspicious_activity'
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String, nullable=True)
    details = Column(JSON, default={})  # Additional event details
    
    user = relationship("User", back_populates="forensic_logs")

class EndpointSession(Base):
    __tablename__ = "endpoint_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"))
    session_start = Column(DateTime, default=datetime.utcnow)
    session_end = Column(DateTime, nullable=True)
    last_heartbeat = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    user = relationship("User")
    endpoint = relationship("Endpoint")

class Attendance(Base):
    __tablename__ = "attendance"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    login_time = Column(DateTime, default=datetime.utcnow)
    logout_time = Column(DateTime, nullable=True)
    working_hours = Column(Float, default=0.0) # In hours
    leave_type = Column(String, nullable=True) # 'casual', 'sick', etc.
    status = Column(String, default="present") # 'present', 'absent', 'on_leave'
    
    # Session tracking fields
    session_token = Column(String, unique=True, index=True, nullable=True)  # Unique session identifier
    last_activity = Column(DateTime, default=datetime.utcnow)  # Track last user activity
    is_active = Column(Boolean, default=True)  # Active session flag
    logout_reason = Column(String, nullable=True)  # 'manual', 'inactivity', 'new_session'
    
    # Device & Browser tracking
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    device_fingerprint = Column(String, nullable=True)
    browser_name = Column(String, nullable=True)
    browser_version = Column(String, nullable=True)
    os_name = Column(String, nullable=True)
    os_version = Column(String, nullable=True)
    
    user = relationship("User")

class PasswordHistory(Base):
    __tablename__ = "password_history"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    hashed_password = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User")

class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    alert_type = Column(String) # 'new_device', 'brute_force', 'suspicious_activity'
    severity = Column(String) # 'low', 'medium', 'high', 'critical'
    description = Column(String)
    is_resolved = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    details = Column(JSON, default={})
    
    user = relationship("User")

class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    ip_address = Column(String)
    success = Column(Boolean)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_agent = Column(String, nullable=True)
    failure_reason = Column(String, nullable=True) # 'incorrect_password', 'account_locked', etc.

class Task(Base):
    __tablename__ = "tasks"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(Text, nullable=True)
    assigned_by_id = Column(Integer, ForeignKey("users.id"))
    assigned_to_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String, default="pending") # 'pending', 'in_progress', 'completed'
    priority = Column(String, default="medium") # 'low', 'medium', 'high'
    created_at = Column(DateTime, default=datetime.utcnow)
    due_date = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    assigned_by = relationship("User", foreign_keys=[assigned_by_id])
    assigned_to = relationship("User", foreign_keys=[assigned_to_id])

class Message(Base):
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"))
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=True) # Null for group/community/department
    department_id = Column(Integer, ForeignKey("departments.id"), nullable=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    content = Column(Text)
    message_type = Column(String) # 'personal', 'community', 'department'
    timestamp = Column(DateTime, default=lambda: datetime.now(IST))
    
    sender = relationship("User", foreign_keys=[sender_id])
    receiver = relationship("User", foreign_keys=[receiver_id])
    department = relationship("Department")
    organization = relationship("Organization")

