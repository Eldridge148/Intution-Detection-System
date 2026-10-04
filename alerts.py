import smtplib
import time
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Gmail SMTP settings
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "eldridgeadomako@gmail.com"
SENDER_PASSWORD = os.environ.get("ALERT_SENDER_PASSWORD")  # Gmail App Password
RECIPIENT_EMAIL = "adomako.e@my.ccsu.edu"


def send_email_alert(event_type, filename, severity):
    subject = f"[SOC ALERT - {severity}] {event_type}: {filename}"
    body = f"""
Security Alert Detected

Event Type:  {event_type}
File:        {filename}
Severity:    {severity}
Time:        {time.strftime('%Y-%m-%d %H:%M:%S')}

This is an automated alert from your file integrity monitoring system.
Please verify this activity was authorized.
"""

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECIPIENT_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())
        server.quit()
        print(f"Alert email sent to {RECIPIENT_EMAIL} for {filename}")
    except Exception as e:
        print(f"Failed to send alert email: {e}")
