import os
import smtplib
from dotenv import load_dotenv

load_dotenv()

# Function to send email using smtplib
def send_email(recipient_email, subject, body):
    sender_email = os.environ.get("sender")
    smtp_email = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    
    print(password)


    message = f"""\
    Subject: {subject}
   
    From: {sender_email}

    {body}"""

    try:
        with smtplib.SMTP("smtp.mailgun.org", 587) as server:
            server.login(smtp_email,password)
            server.sendmail(sender_email, recipient_email, message)
        print("Email sent successfully.")
    except Exception as e:
        print(f"An error occurred while sending email: {e}")
