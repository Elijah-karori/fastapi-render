import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import dotenv
import string, random

dotenv.load_dotenv()

def generate_otp(length=6):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def send_email(receiver_email, subject, body):
    sender_email = "customercare@mejack.xyz"
    username = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    stmp_server=os.environ.get("SMTP_SERVER")

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(stmp_server, 587) as server:
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
            print("Email sent successfully")
    except Exception as e:
        print(f"Error: {e}")

# Example usage

send_email("elijakarori23@gmail.com","test","test message")
