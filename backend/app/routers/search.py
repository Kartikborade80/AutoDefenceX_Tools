from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import models, schemas, database, auth

router = APIRouter(prefix="/search", tags=["search"])

@router.get("/", response_model=schemas.SearchResponse)
def global_search(
    q: str, 
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.get_current_active_user)
):
    if not q or len(q) < 2:
        return {"results": []}

    results = []
    org_id = current_user.organization_id

    # 1. Search Endpoints
    endpoints = db.query(models.Endpoint).filter(
        models.Endpoint.organization_id == org_id,
        (models.Endpoint.hostname.ilike(f"%{q}%")) | (models.Endpoint.ip_address.ilike(f"%{q}%"))
    ).limit(5).all()
    
    for e in endpoints:
        results.append(schemas.SearchResult(
            id=f"endpoint_{e.id}",
            category="endpoint",
            title=e.hostname,
            subtitle=f"IP: {e.ip_address} | Status: {e.status}",
            url=f"/endpoints/{e.id}"
        ))

    # 2. Search Users
    users = db.query(models.User).filter(
        models.User.organization_id == org_id,
        (models.User.username.ilike(f"%{q}%")) | (models.User.full_name.ilike(f"%{q}%")) | (models.User.email.ilike(f"%{q}%"))
    ).limit(5).all()
    
    for u in users:
        results.append(schemas.SearchResult(
            id=f"user_{u.id}",
            category="user",
            title=u.full_name or u.username,
            subtitle=f"Role: {u.role} | Dept: {u.department.name if u.department else 'N/A'}",
            url=f"/users" # Adjust if a specific user detail page exists
        ))

    # 3. Search Tickets
    tickets = db.query(models.Ticket).join(models.User, models.Ticket.user_id == models.User.id).filter(
        models.User.organization_id == org_id,
        models.Ticket.description.ilike(f"%{q}%")
    ).limit(5).all()
    
    for t in tickets:
        results.append(schemas.SearchResult(
            id=f"ticket_{t.id}",
            category="ticket",
            title=f"Ticket #{t.id}",
            subtitle=t.description[:50] + "..." if len(t.description) > 50 else t.description,
            url="/tickets" # Adjust as needed
        ))

    return {"results": results}
