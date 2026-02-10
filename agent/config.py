import os

class AgentConfig:
    SERVER_URL = "http://localhost:8000"
    API_PREFIX = "/api/v1"
    
    # In production, these would be managed securely or via enrollment
    AGENT_I_AM_ADMIN_MANAGED = False
    
    # Local storage for offline mode
    LOCAL_DB_PATH = "agent_data.db"
    
config = AgentConfig()
