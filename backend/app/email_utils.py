import os
from datetime import datetime
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment variables
load_dotenv()

def send_login_email_alert(username: str, login_time: str, ip_address: str, location: str, recipient_email: str):
    """
    Sends a login notification email via Gmail SMTP.
    """
    sender_email = "autodefense.x@gmail.com"
    sender_password = os.environ.get("EMAIL_PASSWORD") # App Password

    if not sender_password:
        print("❌ Email ERROR: EMAIL_PASSWORD not set in environment variables.")
        return False

    try:
        print(f"📧 Email: Sending Login Alert for {username} to {recipient_email} from {sender_email}...")
        
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = f"Login Alert: {username} - AutoDefenceX"

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
                    <td style="padding: 8px; font-weight: bold; color: #64748b;">Location:</td>
                    <td style="padding: 8px;">{location}</td>
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
        
        msg.attach(MIMEText(html_content, 'html'))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
            
        print(f"✅ Email SUCCESS: Alert sent to {recipient_email}")
        return True
    except Exception as e:
        print(f"❌ Email ERROR: {str(e)}")
        return False

def send_otp_email(recipient_email, otp_code):
    """
    Sends a 2FA OTP code via Gmail SMTP.
    """
    sender_email = "autodefense.x@gmail.com"
    sender_password = os.environ.get("EMAIL_PASSWORD") # App Password
    
    if not sender_password:
        print("❌ Email ERROR: EMAIL_PASSWORD not set.")
        return False

    try:
        print(f"📧 Email: Sending OTP to {recipient_email}...")
        
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = f"Your Verification Code: {otp_code}"
        
        html_content = f"""
        <div style="font-family: sans-serif; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px; max-width: 600px;">
            <h2 style="color: #1e293b; text-align: center;">AutoDefenceX Security</h2>
            <p>Your one-time verification code is:</p>
            <div style="background-color: #f1f5f9; padding: 20px; border-radius: 6px; text-align: center; font-size: 2rem; font-weight: bold; letter-spacing: 5px; color: #2563eb; margin: 20px 0;">
                {otp_code}
            </div>
            <p style="font-size: 0.9rem; color: #64748b;">
                This code will expire in 10 minutes. If you did not request this code, please ignore this email.
            </p>
            <hr style="margin: 20px 0; border: 0; border-top: 1px solid #e2e8f0;" />
            <p style="color: #94a3b8; font-size: 0.8rem; text-align: center;">
                Protected by AutoDefenceX Multi-Factor Authentication
            </p>
        </div>
        """
        
        msg.attach(MIMEText(html_content, 'html'))
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
            
        print(f"✅ OTP Email SUCCESS: Sent to {recipient_email}")
        return True
    except Exception as e:
        print(f"❌ OTP Email ERROR: {str(e)}")
        return False
