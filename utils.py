import random
import string
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import qrcode
import io
from flask import current_app
from twilio.rest import Client
import base64

def generate_pin(length=6):
    
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def generate_qr_token(length=20):
    
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def send_email_notification(to_email, subject, body):
    
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = current_app.config['MAIL_USERNAME']
        msg['To'] = to_email

        smtp_server = current_app.config['MAIL_SERVER']
        smtp_port = current_app.config['MAIL_PORT']
        smtp_user = current_app.config['MAIL_USERNAME']
        smtp_password = current_app.config['MAIL_PASSWORD']
        use_tls = current_app.config['MAIL_USE_TLS']

        server = smtplib.SMTP(smtp_server, smtp_port)
        if use_tls:
            server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("Failed to send email:", e)
        return False

def send_whatsapp_message(phone_number, message):
    
    try:
        client = Client(
            current_app.config['TWILIO_ACCOUNT_SID'],
            current_app.config['TWILIO_AUTH_TOKEN']
        )

        from_whatsapp = current_app.config['TWILIO_WHATSAPP_FROM']
        to_whatsapp = f"whatsapp:{phone_number}"  

        message = client.messages.create(
            body=message,
            from_=from_whatsapp,
            to=to_whatsapp
        )
        return True
    except Exception as e:
        print(f"[WHATSAPP ERROR] Failed to send message to {phone_number}: {e}")
        return False

def generate_qr_code(data):
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)

    return base64.b64encode(buffer.getvalue()).decode()

def calculate_attendance_percentage(present_count, total_count):
    
    if total_count == 0:
        return 0
    return (present_count / total_count) * 100

def is_low_attendance(percentage, threshold=75):
    
    return percentage < threshold

def format_attendance_alert(student_name, date, subject):
    
    return f"Alert: {student_name} was absent on {date} for {subject}"

def format_monthly_report(student_name, total_classes, present_count, percentage):
    
    return f"""
Monthly Attendance Report - {student_name}

Total Classes: {total_classes}
Present: {present_count}
Attendance Percentage: {percentage:.1f}%

Status: {'Good' if percentage >= 75 else 'Needs Improvement' if percentage >= 60 else 'Critical'}
"""

def validate_phone_number(phone):
    
    
    digits = ''.join(filter(str.isdigit, phone))
    
    return 10 <= len(digits) <= 15

def validate_email(email):
    
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def get_academic_year():
    
    now = datetime.now()
    if now.month >= 4:  
        return f"{now.year}-{now.year + 1}"
    else:
        return f"{now.year - 1}-{now.year}"

def get_days_in_month(year, month):
    
    import calendar
    return calendar.monthrange(year, month)[1]

def generate_attendance_chart_data(attendance_records):
    
    daily_data = {}
    for record in attendance_records:
        date_str = record.date.strftime('%Y-%m-%d')
        if date_str not in daily_data:
            daily_data[date_str] = {'present': 0, 'absent': 0}

        if record.status == 'Present':
            daily_data[date_str]['present'] += 1
        else:
            daily_data[date_str]['absent'] += 1

    return daily_data

class AttendanceCalculator:
    

    @staticmethod
    def calculate_monthly_percentage(student_id, year, month):
        
        from models import Attendance
        from datetime import date

        start_date = date(year, month, 1)
        if month == 12:
            end_date = date(year + 1, 1, 1)
        else:
            end_date = date(year, month + 1, 1)

        records = Attendance.query.filter(
            Attendance.student_id == student_id,
            Attendance.date >= start_date,
            Attendance.date < end_date
        ).all()

        if not records:
            return 0

        present_count = len([r for r in records if r.status == 'Present'])
        return (present_count / len(records)) * 100

    @staticmethod
    def get_subject_wise_attendance(student_id):
        
        from models import Attendance
        from collections import defaultdict

        records = Attendance.query.filter_by(student_id=student_id).all()
        subject_data = defaultdict(lambda: {'present': 0, 'total': 0})

        for record in records:
            subject_data[record.subject]['total'] += 1
            if record.status == 'Present':
                subject_data[record.subject]['present'] += 1

        result = {}
        for subject, data in subject_data.items():
            percentage = (data['present'] / data['total']) * 100 if data['total'] > 0 else 0
            result[subject] = {
                'percentage': percentage,
                'present': data['present'],
                'total': data['total']
            }

        return result
