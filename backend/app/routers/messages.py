from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import models, schemas, auth, database

router = APIRouter(prefix="/messages", tags=["messages"])

@router.post("/", response_model=schemas.Message)
def send_message(message: schemas.MessageCreate, db: Session = Depends(database.get_db)):
    db_message = models.Message(**message.dict())
    db.add(db_message)
    db.commit()
    db.refresh(db_message)
    return db_message

@router.get("/personal/{user_id}", response_model=List[schemas.Message])
def get_personal_messages(user_id: int, db: Session = Depends(database.get_db)):
    messages = db.query(models.Message).filter(
        (models.Message.message_type == "personal") & 
        ((models.Message.sender_id == user_id) | (models.Message.receiver_id == user_id))
    ).all()
    # Enrich with sender name
    for msg in messages:
        if msg.sender:
            msg.sender_name = msg.sender.full_name or msg.sender.username
    return messages

@router.get("/department/{dept_id}", response_model=List[schemas.Message])
def get_department_messages(dept_id: int, db: Session = Depends(database.get_db)):
    messages = db.query(models.Message).filter(
        (models.Message.message_type == "department") & 
        (models.Message.department_id == dept_id)
    ).all()
    for msg in messages:
        if msg.sender:
            msg.sender_name = msg.sender.full_name or msg.sender.username
    return messages

@router.get("/community/{org_id}", response_model=List[schemas.Message])
def get_community_messages(org_id: int, db: Session = Depends(database.get_db)):
    messages = db.query(models.Message).filter(
        (models.Message.message_type == "community") & 
        (models.Message.organization_id == org_id)
    ).all()
    for msg in messages:
        if msg.sender:
            msg.sender_name = msg.sender.full_name or msg.sender.username
    return messages
