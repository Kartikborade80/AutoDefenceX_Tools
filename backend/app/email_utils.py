import resend
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Resend API Configuration
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "DEACTIVATED")
resend.api_key = RESEND_API_KEY

def send_login_email_alert(username: str, login_time: str, ip_address: str, recipient_email: str = "autodefense.x@gmail.com"):
    """
    Sends a login notification email via Resend.
    """
    try:
        print(f"📧 Email: Sending Login Alert for {username} to {recipient_email}...")
        
        html_content = f"""
        <div style="font-family: sans-serif; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px; max-width: 600px;">
            <h2 style="color: #1e293b;">Login Alert: AutoDefenceX</h2>
            <p>A new login was detected on your account.</p>
            <table style="width: 100%; border-collapse: collapse; margin-top: 15px;">
                <tr>
                    <td style="padding: 8px; font-weight: bold; color: #64748b;">User:</td>
                    <td style="padding: 8px;">{username}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; font-weight: bold; color: #64748b;">Time:</td>
                    <td style="padding: 8px;">{login_time}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; font-weight: bold; color: #64748b;">IP Address:</td>
                    <td style="padding: 8px;">{ip_address}</td>
                </tr>
            </table>
            <p style="margin-top: 20px; color: #ef4444; font-size: 0.9rem;">
                If this activity was not done by you, please secure your account immediately.
            </p>
            <hr style="margin: 20px 0; border: 0; border-top: 1px solid #e2e8f0;" />
            <p style="color: #94a3b8; font-size: 0.8rem;">
                This is an automated security notification from AutoDefenceX.
            </p>
        </div>
        """
        
        params = {
            "from": "onboarding@resend.dev",
            "to": recipient_email,
            "subject": f"Login Alert: {username} - AutoDefenceX",
            "html": html_content
        }
        
        email = resend.Emails.send(params)
        print(f"✅ Email SUCCESS: Alert sent. ID: {email.get('id')}")
        return True
    except Exception as e:
        print(f"❌ Email ERROR: {str(e)}")
        return False
