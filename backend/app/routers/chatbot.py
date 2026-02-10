from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
import os
from google import genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

router = APIRouter(
    prefix="/chatbot",
    tags=["chatbot"],
)

# Configure Gemini API from environment variable
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyA8LdcAaaSBEuGTV6jD4HEvKDSrY8L6TOI")
client = genai.Client(api_key=GEMINI_API_KEY)

# AutoDefenceX context for the AI
AUTODEFENCEX_CONTEXT = """
You are Sentra, an AI assistant for AutoDefenceX, a multi-tenant cybersecurity platform. Your role is to help users manage their organization's security while ensuring strict data isolation.

Core Identity:
- You are Sentra, the intelligent automation assistant for AutoDefenceX.
- Data Privacy: "One organization, one data." You never show data from other companies.
- Multi-Tenancy: Each admin only sees their company's users, departments, and endpoints.

Live Features:
1. **Live Company Branding**: When users type their username on the login screen, their company name is dynamically displayed.
2. **Organization Isolation**: Admins can only manage resources (User, Policies, Endpoints) within their assigned organization.
3. **Automated User Setup**: Auto-generates Pune-style Indian employee names, IDs, and passwords ([username]@123).

Management Workflows:
- Admin View: Only shows your company's departments and staff.
- Reports: Security and compliance reports are strictly scoped to your organization.
- Policies: Apply security rules (USB block, etc.) across your company's users.

Always reassure users that their data is isolated and secure within their specific organization. Provide help based on the specific company they are managing.

FORMATTING RULES:
1. ALWAYS use numbered lists or bullet points for instructions.
2. Keep responses concise and "point-wise".
3. Avoid long paragraphs.
4. Structure the output as a clear process.
"""

class ChatMessage(BaseModel):
    message: str
    conversation_history: Optional[list] = []

@router.post("/chat")
async def chat_with_ai(chat_request: ChatMessage):
    """
    Handle chat requests using Google Gemini AI (New SDK)
    """
    try:
        # Build prompt with context
        full_prompt = f"{AUTODEFENCEX_CONTEXT}\n\nUser Question: {chat_request.message}\n\nProvide a helpful, concise answer about AutoDefenceX:"
        
        # Generate response using Gemini 3 Flash Preview
        response = client.models.generate_content(
            model="gemini-3-flash-preview",
            contents=full_prompt
        )
        
        return {
            "response": response.text,
            "success": True
        }
    
    except Exception as e:
        print(f"Chatbot Error: {str(e)}")  # Log the error
        import traceback
        traceback.print_exc()  # Print full traceback
        raise HTTPException(status_code=500, detail=f"AI Error: {str(e)}")

@router.get("/health")
async def chatbot_health():
    """Check if chatbot service is available"""
    return {"status": "online", "model": "gemini-3-flash-preview"}
