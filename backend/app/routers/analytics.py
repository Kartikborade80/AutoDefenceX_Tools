from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from .. import auth, models, database, crud, websockets
from .endpoints import isolate_endpoint_logic, kill_process_logic # Import logic from endpoints
from datetime import datetime
import random
import asyncio

router = APIRouter(prefix="/analytics", tags=["analytics"])

# Simulated Vulnerability Database
VULNERABILITY_DB = [
    {"name": "Google Chrome", "version_prefix": "100.", "cve": "CVE-2022-1096", "severity": "high", "description": "Critical flaw in JavaScript engine."},
    {"name": "Mozilla Firefox", "version_prefix": "97.", "cve": "CVE-2022-26485", "severity": "critical", "description": "Use-after-free in XSLT parameter processing."},
    {"name": "Node.js", "version_prefix": "16.", "cve": "CVE-2022-32213", "severity": "medium", "description": "HTTP Request Smuggling via llhttp."},
    {"name": "Microsoft Edge", "version_prefix": "99.", "cve": "CVE-2022-24534", "severity": "high", "description": "Remote code execution vulnerability."},
    {"name": "Docker Desktop", "version_prefix": "4.6.", "cve": "CVE-2022-29074", "severity": "medium", "description": "Privilege escalation via symlink attack."},
    {"name": "VS Code", "version_prefix": "1.65.", "cve": "CVE-2022-24519", "severity": "low", "description": "Spoofing vulnerability in editor."},
]

@router.get("/vulnerabilities/{endpoint_id}")
async def get_vulnerabilities(endpoint_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """Map installed software to known vulnerabilities (CVEs)"""
    # Return rich dummy data for demonstration
    return {
        "endpoint_id": endpoint_id,
        "vulnerabilities": [
            {
                "cve": "CVE-2024-3094",
                "severity": "critical",
                "software": "xz-utils 5.6.1",
                "description": "Malicious code discovered in the upstream tarballs of xz, leading to remote code execution."
            },
            {
                "cve": "CVE-2023-4863",
                "severity": "high",
                "software": "Google Chrome 116.0.5845.96",
                "description": "Heap buffer overflow in libwebp allowing a remote attacker to perform an out of bounds memory write via a crafted HTML page."
            },
            {
                "cve": "CVE-2023-38545",
                "severity": "medium",
                "software": "curl 8.3.0",
                "description": "SOCKS5 heap buffer overflow when the hostname is longer than 255 bytes."
            }
        ]
    }
    # The original logic below is commented out as per the instruction to return dummy data.
    # endpoint = db.query(models.Endpoint).filter(models.Endpoint.id == endpoint_id).first()
    # if not endpoint:
    #     raise HTTPException(status_code=404, detail="Endpoint not found")
    
    # if endpoint.organization_id != current_user.organization_id:
    #     raise HTTPException(status_code=403, detail="Unauthorized access")
    
    # system_info = endpoint.system_info
    # if not system_info or not system_info.installed_software:
    #     return {"endpoint_hostname": endpoint.hostname, "vulnerabilities": []}
    
    # found_vulnerabilities = []
    # software_list = system_info.installed_software # List of strings like ["Google Chrome 100.0.123", "Node.js 16.2.1"]
    
    # for software in software_list:
    #     for vuln in VULNERABILITY_DB:
    #         if vuln["name"].lower() in software.lower() and vuln["version_prefix"] in software:
    #             found_vulnerabilities.append({
    #                 "software": software,
    #                 "cve": vuln["cve"],
    #                 "severity": vuln["severity"],
    #                 "description": vuln["description"]
    #             })
                
    # return {
    #     "endpoint_hostname": endpoint.hostname,
    #     "vulnerabilities": found_vulnerabilities,
    #     "total_count": len(found_vulnerabilities)
    # }

@router.get("/benchmarks")
async def get_ai_benchmarks(db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """Fetch AI-generated security benchmarking and insights"""
    # In a production app, this would call Gemini to analyze current org metrics
    # against industry standards. For this phase, we return high-fidelity simulated insights.
    
    # Return rich dummy data for demonstration
    return {
        "global_rank": "#42 / 500",
        "industry_percentile": 88,
        "insights": [
             {
                "category": "Identity Security",
                "score": 92,
                "benchmark": 85,
                "insight": "Strong MFA adoption. 98% of admin accounts are protected.",
                "recommendation": "Consider phasing out SMS OTP for FIDO2 keys."
            },
            {
                "category": "Endpoint Hygiene",
                "score": 65,
                "benchmark": 80,
                "insight": "Multiple endpoints have outdated software with known CVEs.",
                "recommendation": "Prioritize patching for CVE-2024-3094 immediately."
            },
            {
                "category": "Network Traffic",
                "score": 78,
                "benchmark": 75,
                "insight": "Unusual outbound traffic detected from 2 isolated nodes.",
                "recommendation": "Investigate traffic logs for potential C2 communication."
            }
        ]
    }
    # The original logic below is commented out as per the instruction to return dummy data.
    # insights = [
    #     {
    #         "category": "Endpoint Hygiene",
    #         "score": 78,
    #         "benchmark": 85,
    #         "insight": "Your organization is 7% below BFSI industry benchmarks for patch application speed.",
    #         "recommendation": "Accelerate critical vulnerability remediation for Chrome and Node.js assets."
    #     },
    #     {
    #         "category": "Identity Security",
    #         "score": 92,
    #         "benchmark": 80,
    #         "insight": "Strong performance in MFA compliance across Department Heads.",
    #         "recommendation": "Expand Master OTP bypass restrictions to shared administrative workstations."
    #     },
    #     {
    #         "category": "Network Containment",
    #         "score": 65,
    #         "benchmark": 75,
    #         "insight": "High lateral movement risk detected in Marketing department endpoints.",
    #         "recommendation": "Deploy strict VLAN isolation policies for non-technical departments."
    #     }
    # ]
    
    # return {
    #     "organization": "Security Intelligence Score",
    #     "global_rank": "Top 15%",
    #     "last_updated": datetime.now().isoformat(),
    #     "insights": insights
    # }

@router.get("/topology")
async def get_network_topology(db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """Generate node-link data for interactive network visualization"""
    endpoints = db.query(models.Endpoint).filter(models.Endpoint.organization_id == current_user.organization_id).all()
    
    nodes = []
    links = []
    
    nodes.append({
        "id": "gateway-0",
        "label": "Secure Gateway",
        "type": "gateway",
        "status": "online"
    })
    
    for ep in endpoints:
        nodes.append({
            "id": f"endpoint-{ep.id}",
            "label": ep.hostname,
            "type": "endpoint",
            "status": ep.status,
            "risk": ep.risk_level
        })
        
        # Simple connectivity model: All endpoints connect to gateway
        links.append({
            "source": "gateway-0",
            "target": f"endpoint-{ep.id}",
            "value": 1
        })
        
    return {"nodes": nodes, "links": links}

@router.post("/playbooks/run")
async def run_autonomous_playbooks(db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    """Evaluate and execute automated security playbooks across the organization"""
    endpoints = db.query(models.Endpoint).filter(models.Endpoint.organization_id == current_user.organization_id).all()
    
    actions_taken = []
    
    for ep in endpoints:
        sys_info = ep.system_info
        
        # Rule 1: High Risk Critical Isolation
        if ep.risk_level == 'critical' and ep.status == 'online':
            # Auto-Isolate
            result = await isolate_endpoint_logic(ep.id, db, current_user, "Autonomous Playbook: Critical Risk Isolation")
            actions_taken.append({
                "endpoint": ep.hostname,
                "rule": "Critical Risk Auto-Isolation",
                "action": "Isolated",
                "status": "Success" if result else "Failed"
            })
            
        # Rule 2: Malicious Process Termination
        if sys_info and sys_info.running_processes:
            malicious_patterns = ["miner.exe", "ransom.exe", "backdoor.exe", "mimikatz"]
            for proc in sys_info.running_processes:
                proc_name = proc.get("Name", "").lower()
                if any(pattern in proc_name for pattern in malicious_patterns):
                    # Auto-Kill
                    try:
                        await kill_process_logic(ep.id, proc.get("Id"), db, current_user)
                        actions_taken.append({
                            "endpoint": ep.hostname,
                            "rule": f"Malicious Process Cleanup ({proc_name})",
                            "action": "Process Terminated",
                            "status": "Success"
                        })
                    except:
                        actions_taken.append({
                            "endpoint": ep.hostname,
                            "rule": f"Malicious Process Cleanup ({proc_name})",
                            "action": "Process Terminated",
                            "status": "Failed"
                        })

    # Log the activity
    if actions_taken:
         activity = models.ActivityLog(
            user_id=current_user.id,
            action="autonomous_playbook_run",
            details={"actions": actions_taken},
            timestamp=datetime.utcnow()
        )
         db.add(activity)
         db.commit()
         
         # Notify via WebSocket
         await websockets.manager.broadcast_to_org(current_user.organization_id, {
             "type": "playbook_execution",
             "data": {"actions": actions_taken, "count": len(actions_taken)}
         })

    return {
        "status": "completed",
        "actions_count": len(actions_taken),
        "actions": actions_taken,
        "timestamp": datetime.now().isoformat()
    }
