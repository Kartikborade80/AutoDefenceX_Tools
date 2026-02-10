from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

# --- System Info ---
class SystemInfoBase(BaseModel):
    cpu_usage: float
    ram_usage: float
    total_ram: float
    disk_usage: Dict[str, Any]
    running_processes: List[Dict[str, Any]]
    installed_software: List[str]

class SystemInfoCreate(SystemInfoBase):
    pass

class SystemInfo(SystemInfoBase):
    id: int
    updated_at: datetime
    class Config:
        from_attributes = True

# --- Scans ---
class ScanResultBase(BaseModel):
    scan_type: str
    status: str
    findings: List[Any]
    security_score: Optional[int] = 0
    scan_progress: Optional[int] = 0
    threat_count: Optional[int] = 0
    defender_status: Optional[str] = None
    system_health: Optional[Dict[str, Any]] = {}

class ScanResultCreate(ScanResultBase):
    pass

class ScanResult(ScanResultBase):
    id: int
    started_at: datetime
    completed_at: Optional[datetime]
    class Config:
        from_attributes = True

# --- Endpoint ---
class EndpointBase(BaseModel):
    hostname: str
    ip_address: str
    mac_address: Optional[str] = None
    os_details: Optional[str] = None
    status: str = "offline"
    risk_level: str = "low"

class EndpointCreate(EndpointBase):
    pass

class Endpoint(EndpointBase):
    id: int
    trust_score: int
    last_seen: datetime
    system_info: Optional[SystemInfo] = None
    
    class Config:
        from_attributes = True # updated for Pydantic v2 support if needed



# --- Activity Log ---
class ActivityLogBase(BaseModel):
    action: str
    details: Dict[str, Any]

class ActivityLogCreate(ActivityLogBase):
    pass

class ActivityLog(ActivityLogBase):
    id: int
    user_id: int
    timestamp: datetime
    class Config:
        from_attributes = True

class LoginAttemptBase(BaseModel):
    username: str
    ip_address: str
    success: bool
    user_agent: Optional[str] = None
    failure_reason: Optional[str] = None

class LoginAttempt(LoginAttemptBase):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True

# --- Search ---
class SearchResult(BaseModel):
    id: str # model_id (e.g., 'endpoint_1')
    category: str # 'endpoint', 'user', 'ticket'
    title: str
    subtitle: Optional[str] = None
    url: str

class SearchResponse(BaseModel):
    results: List[SearchResult]

class SecurityAlertBase(BaseModel):
    alert_type: str
    severity: str
    description: str
    is_resolved: bool = False
    details: Dict[str, Any] = {}
    user_id: Optional[int] = None

class SecurityAlert(SecurityAlertBase):
    id: int
    timestamp: datetime
    
    class Config:
        from_attributes = True

# --- Endpoint Alerts ---
class AlertBase(BaseModel):
    title: str
    description: str
    severity: str
    is_resolved: bool = False

class AlertCreate(AlertBase):
    endpoint_id: int

class Alert(AlertBase):
    id: int
    endpoint_id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

class EndpointDetail(Endpoint):
    scans: List[ScanResult] = []
    alerts: List[Alert] = []

# --- Ticket ---
class TicketBase(BaseModel):
    category: Optional[str] = None
    description: str
    assigned_to_user_id: Optional[int] = None
    department_id: Optional[int] = None

class TicketCreate(TicketBase):
    pass

class Ticket(TicketBase):
    id: int
    user_id: int
    status: str
    created_at: datetime
    class Config:
        from_attributes = True

# --- User ---
class UserBase(BaseModel):
    username: str
    role: str = "viewer"
    full_name: Optional[str] = None
    mobile_number: Optional[str] = None
    employee_id: Optional[str] = None
    asset_id: Optional[str] = None
    job_title: Optional[str] = None
    is_normal_user: Optional[bool] = False # True = User, False = Agent/Endpoint
    is_department_head: Optional[bool] = False
    access_control: Dict[str, bool] = {}
    company_name: Optional[str] = None
    company_address: Optional[str] = None
    company_domain: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    department_id: Optional[int] = None
    designation_code: Optional[str] = None
    account_type: Optional[str] = None
    device_id: Optional[str] = None
    os_type: Optional[str] = None
    hostname: Optional[str] = None
    access_expiry: Optional[datetime] = None
    password_expiry_days: Optional[int] = 90
    force_password_change: Optional[bool] = False
    created_by: Optional[str] = None

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    mobile_number: Optional[str] = None
    job_title: Optional[str] = None
    asset_id: Optional[str] = None
    is_normal_user: Optional[bool] = None
    access_control: Optional[Dict[str, bool]] = None
    department_id: Optional[int] = None
    is_head_admin: Optional[bool] = False
    is_department_head: Optional[bool] = False
    designation_code: Optional[str] = None
    account_type: Optional[str] = None
    device_id: Optional[str] = None
    os_type: Optional[str] = None
    hostname: Optional[str] = None
    access_expiry: Optional[datetime] = None
    password_expiry_days: Optional[int] = None
    force_password_change: Optional[bool] = None


class AdminRegisterCreate(BaseModel):
    username: str
    password: str
    full_name: str
    email: str
    company_name: Optional[str] = None
    company_address: Optional[str] = None
    company_domain: Optional[str] = None
    phone: Optional[str] = None

class PublicUserCreate(BaseModel):
    username: str
    password: str
    full_name: str
    mobile_number: Optional[str] = None

class User(UserBase):
    id: int
    is_active: bool
    is_head_admin: bool = False
    created_at: datetime
    risk_score: float
    last_login: Optional[datetime] = None
    department_id: Optional[int] = None
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user_info: Optional[Dict[str, Any]] = None

class TokenResponse(Token):
    otp_required: bool = False
    phone_masked: Optional[str] = None

class TokenData(BaseModel):
    username: Optional[str] = None

# --- Department ---
class DepartmentBase(BaseModel):
    name: str
    description: Optional[str] = None
    hod_id: Optional[int] = None
    monitoring_enabled: bool = False

class DepartmentCreate(DepartmentBase):
    pass

class Department(DepartmentBase):
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

# --- Policy ---
class PolicyBase(BaseModel):
    name: str
    policy_type: str
    enabled: bool = False
    config: Dict[str, Any] = {}
    department_id: Optional[int] = None
    applied_to_user_id: Optional[int] = None

class PolicyCreate(PolicyBase):
    pass

class PolicyUpdate(BaseModel):
    enabled: Optional[bool] = None
    config: Optional[Dict[str, Any]] = None
    applied_to_user_id: Optional[int] = None

class Policy(PolicyBase):
    id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

# --- Forensic Log ---
class ForensicLogBase(BaseModel):
    event_type: str
    ip_address: Optional[str] = None
    details: Dict[str, Any] = {}

class ForensicLogCreate(ForensicLogBase):
    user_id: int

class ForensicLog(ForensicLogBase):
    id: int
    user_id: int
    timestamp: datetime
    
    class Config:
        from_attributes = True

# --- Endpoint Session ---
class EndpointSessionBase(BaseModel):
    user_id: int
    endpoint_id: int

class EndpointSessionCreate(EndpointSessionBase):
    pass

class EndpointSession(EndpointSessionBase):
    id: int
    session_start: datetime
    session_end: Optional[datetime] = None
    last_heartbeat: datetime
    is_active: bool
    
    class Config:
        from_attributes = True

class ConnectedEndpoint(BaseModel):
    session_id: int
    endpoint_id: int
    user_id: int
    hostname: str
    ip_address: str
    full_name: str
    employee_id: str
    department_name: str
    job_title: str
    session_start: datetime
    status: str # online, away, etc.

    class Config:
        from_attributes = True

# --- Organization ---
class OrganizationBase(BaseModel):
    name: str
    domain: Optional[str] = None
    address: Optional[str] = None

class OrganizationCreate(OrganizationBase):
    pass

class Organization(OrganizationBase):
    id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

# --- Attendance ---
class AttendanceBase(BaseModel):
    user_id: int
    login_time: datetime
    logout_time: Optional[datetime] = None
    working_hours: float = 0.0
    leave_type: Optional[str] = None
    status: str = "present"

class AttendanceCreate(BaseModel):
    user_id: int
    login_time: Optional[datetime] = None

class AttendanceUpdate(BaseModel):
    logout_time: Optional[datetime] = None
    working_hours: Optional[float] = None
    leave_type: Optional[str] = None
    status: Optional[str] = None

class Attendance(AttendanceBase):
    id: int
    class Config:
        from_attributes = True

# --- Task ---
class TaskBase(BaseModel):
    title: str
    description: Optional[str] = None
    assigned_to_id: int
    status: str = "pending"
    priority: str = "medium"
    due_date: Optional[datetime] = None

class TaskCreate(TaskBase):
    assigned_by_id: int

class TaskUpdate(BaseModel):
    status: Optional[str] = None
    completed_at: Optional[datetime] = None

class Task(TaskBase):
    id: int
    assigned_by_id: int
    created_at: datetime
    completed_at: Optional[datetime] = None
    class Config:
        from_attributes = True

# --- Message ---
class MessageBase(BaseModel):
    sender_id: int
    content: str
    message_type: str # 'personal', 'community', 'department'
    receiver_id: Optional[int] = None
    department_id: Optional[int] = None
    organization_id: int

class MessageCreate(MessageBase):
    pass

class Message(MessageBase):
    id: int
    timestamp: datetime
    sender_name: Optional[str] = None
    
    class Config:
        from_attributes = True
