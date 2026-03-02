from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import json
import traceback

from .. import auth, models, database

router = APIRouter(prefix="/topology", tags=["topology"])


class TopologySaveRequest(BaseModel):
    name: Optional[str] = "Default Topology"
    topology_data: dict  # {devices: [...], connections: [...]}


@router.post("/save")
async def save_topology(
    request: TopologySaveRequest,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Save or update a network topology map for the user's organization."""
    if not current_user.organization_id:
        raise HTTPException(status_code=400, detail="User is not part of an organization")
    
    existing = db.query(models.NetworkTopologyMap).filter(
        models.NetworkTopologyMap.organization_id == current_user.organization_id
    ).first()
    
    if existing:
        existing.topology_data = json.dumps(request.topology_data)
        existing.name = request.name or existing.name
        existing.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(existing)
        return {
            "success": True,
            "message": "Topology updated successfully",
            "id": existing.id,
            "updated_at": existing.updated_at.isoformat()
        }
    else:
        new_topology = models.NetworkTopologyMap(
            organization_id=current_user.organization_id,
            name=request.name or "Default Topology",
            topology_data=json.dumps(request.topology_data),
            created_by=current_user.id
        )
        db.add(new_topology)
        db.commit()
        db.refresh(new_topology)
        return {
            "success": True,
            "message": "Topology saved successfully",
            "id": new_topology.id,
            "created_at": new_topology.created_at.isoformat()
        }


@router.get("/load")
async def load_topology(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Load the saved network topology for the user's organization."""
    if not current_user.organization_id:
        return {"success": True, "topology": None, "message": "No organization found"}
    
    topology = db.query(models.NetworkTopologyMap).filter(
        models.NetworkTopologyMap.organization_id == current_user.organization_id
    ).first()
    
    if topology:
        return {
            "success": True,
            "topology": {
                "id": topology.id,
                "name": topology.name,
                "data": json.loads(topology.topology_data) if topology.topology_data else {"devices": [], "connections": []},
                "updated_at": topology.updated_at.isoformat() if topology.updated_at else None
            }
        }
    else:
        return {
            "success": True,
            "topology": None,
            "message": "No topology found. Create one by placing devices on the canvas."
        }


@router.delete("/clear")
async def clear_topology(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    """Delete the saved topology for the user's organization."""
    if not current_user.organization_id:
        raise HTTPException(status_code=400, detail="User is not part of an organization")
    
    deleted = db.query(models.NetworkTopologyMap).filter(
        models.NetworkTopologyMap.organization_id == current_user.organization_id
    ).delete()
    
    db.commit()
    return {
        "success": True,
        "message": f"Topology cleared ({deleted} record(s) deleted)"
    }


    return {
        "success": True,
        "message": f"Topology cleared ({deleted} record(s) deleted)"
    }
