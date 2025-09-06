import os
from datetime import datetime, timedelta, date
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort, current_app
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from calendar import monthrange
import qrcode
from werkzeug.utils import secure_filename
from utils import send_email_notification, send_whatsapp_message
import io
import base64
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from difflib import SequenceMatcher
import re
import string
import random
from models import *
from analytics import AttendanceAnalytics
from config import Config
import json
from extensions import db, login_manager  

app = Flask(__name__)
from flask_migrate import Migrate


migrate = Migrate(app, db)

app.config.from_object(Config)


db.init_app(app)  
login_manager.init_app(app)
login_manager.login_view = 'login'


from models import *

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


from models import User, InstitutionDetails, Pin, TeacherClassAssignment, Attendance, ParentContact, PromotionLog, QRCodeSession


@app.route('/')
@app.route('/home')
def index():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()

        if user and check_password_hash(user.password, password):
            if user.status != 'active':
                flash('Your account is pending approval.', 'warning')
                return redirect(url_for('login'))

            login_user(user)
            session.permanent = True
            
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            elif user.role == 'student':
                return redirect(url_for('student_dashboard'))
            elif user.role == 'parent':
                return redirect(url_for('parent_dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if 'send_otp' in request.form:
            email = request.form.get('email')
            role = request.form.get('role')

            if User.query.filter_by(email=email).first():
                flash('Email is already registered.', 'error')
                return render_template('register.html')

            otp = random.randint(100000, 999999)
            session['otp'] = str(otp)
            session['otp_email'] = email
            session['otp_role'] = role
            session['otp_verified'] = False

            try:
                msg = Message('Your OTP for Registration', recipients=[email])
                msg.body = f'Your OTP for registration is: {otp}'
                mail.send(msg)
                flash('OTP sent to your email.', 'success')
            except Exception as e:
                print("Email send error:", e)
                flash('Failed to send OTP. Try again later.', 'error')

            return redirect(url_for('verify_otp'))

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        secure_pin = request.form.get('secure_pin', '')

        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('register.html')

        
        if role == 'admin':
            user = User(
                username=username,
                email=email,
                password=generate_password_hash(password),
                role=role,
                status='active'
            )
            db.session.add(user)
            db.session.flush()

            institution = InstitutionDetails(
                admin_id=user.id,
                name=request.form.get('name', '').strip(),
                type=request.form.get('type', '').strip(),
                country=request.form.get('country', '').strip(),
                state=request.form.get('state', '').strip(),
                city=request.form.get('city', '').strip(),
                medium=request.form.get('medium', '').strip(),
                classes=request.form.get('classes', '').strip(),
                streams=request.form.get('streams', '').strip(),
                degrees=request.form.get('degrees', '').strip()
            )
            db.session.add(institution)
            db.session.flush()

            user.institution_id = institution.id
            db.session.commit()

            flash('Admin registration successful!', 'success')
            return redirect(url_for('login'))

        
        institution_id = None
        if role in ['teacher', 'student']:
            pin = Pin.query.filter_by(pin_code=secure_pin, role=role).first()
            if not pin:
                flash('Invalid or mismatched PIN.', 'error')
                return render_template('register.html')

            institution_id = pin.institution_id
            institution = InstitutionDetails.query.get(institution_id)

            if not institution:
                flash('PIN is not linked to any institution.', 'error')
                return render_template('register.html')

            
            domain_restriction = institution.allowed_domain
            if domain_restriction:
                if not email.lower().endswith(domain_restriction.lower()):
                    flash(f'Registration requires an email ending with "{domain_restriction}".', 'error')
                    return render_template('register.html')

        
        if role == 'parent':
            parent_contact = ParentContact.query.filter(func.lower(ParentContact.email) == email.lower()).first()
            if not parent_contact:
                flash('This email is not registered as a parent for any student.', 'error')
                return render_template('register.html')
            status = 'active'
        else:
            status = 'pending'

        
        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role=role,
            status=status,
            institution_id=institution_id
        )

        if role in ['student', 'teacher']:
            user.class_name = request.form.get('class_name', '')
            user.stream_or_semester = request.form.get('stream_or_semester', '')
            if role == 'student':
                subjects = request.form.getlist('subject')
                user.subject = ', '.join(subjects) if subjects else ''
                user.degree = request.form.get('degree', '')
                user.roll_number = request.form.get('roll_number', '').strip()
            elif role == 'teacher':
                user.subject = request.form.get('subject', '')
                user.degree = request.form.get('degree', '')

        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Awaiting approval.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

from flask_mail import Message
from extensions import mail  
mail.init_app(app)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'forgot_email' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        email = session['forgot_email']

        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(new_password)  
            db.session.commit()
            session.pop('forgot_email', None)
            session.pop('forgot_otp', None)
            flash('Password reset successful. You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('User not found.', 'danger')

    return render_template('reset_password.html')

@app.route('/send-forgot-otp', methods=['POST'])
def send_forgot_otp():
    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': False, 'message': 'Email not found in our system.'}), 404

    otp = random.randint(100000, 999999)
    session['forgot_otp'] = str(otp)
    session['forgot_email'] = email

    try:
        msg = Message('OTP for Password Reset', recipients=[email])
        msg.body = f'Your OTP for password reset is: {otp}'
        mail.send(msg)
        return jsonify({'success': True})
    except Exception as e:
        print("Email send error:", e)
        return jsonify({'success': False, 'message': 'Failed to send OTP.'}), 500

@app.route('/verify-forgot-otp', methods=['POST'])
def verify_forgot_otp():
    data = request.get_json()
    input_otp = data.get('otp')

    if input_otp == session.get('forgot_otp'):
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Invalid OTP'}), 400

@app.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get('email')
    role = data.get('role')

    
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email is already registered.'}), 400

    
    otp = random.randint(100000, 999999)

    
    session['otp'] = str(otp)
    session['otp_email'] = email
    session['otp_role'] = role

    
    try:
        msg = Message('Your OTP for Registration', recipients=[email])
        msg.body = f'Your OTP for registration is: {otp}'
        mail.send(msg)
        return jsonify({'success': True})
    except Exception as e:
        print("Email send error:", e)
        return jsonify({'success': False, 'message': 'Email sending failed.'}), 500

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session.get('otp'):
            session['otp_verified'] = True
            return 'OTP verified successfully'
        return 'Invalid OTP'

    return render_template('verify_otp.html')

@app.route('/get-registration-options', methods=['POST'])
def get_registration_options():
    data = request.get_json()
    pin_code = data.get('pin')
    role = data.get('role')

    
    pin = Pin.query.filter_by(pin_code=pin_code, role=role).first()
    if not pin:
        return jsonify({'error': 'Invalid or mismatched PIN'}), 400

    institution = InstitutionDetails.query.get(pin.institution_id)
    if not institution:
        return jsonify({'error': 'Institution not found'}), 404

    
    classes = [cls.strip() for cls in institution.classes.split(',')] if institution.classes else []
    streams = [s.strip() for s in institution.streams.split(',')] if institution.streams else []
    degrees = [d.strip() for d in institution.degrees.split(',')] if institution.degrees else []

    
    subjects = []
    if role in ['teacher', 'student']:
        
        teacher_ids = db.session.query(User.id).filter_by(role='teacher', institution_id=institution.id).subquery()
        assignments = TeacherClassAssignment.query.filter(
            TeacherClassAssignment.teacher_id.in_(teacher_ids)
        ).all()
        subjects = list({a.subject for a in assignments})

    return jsonify({
        'classes': classes,
        'streams': streams,
        'subjects': subjects,
        'degrees': degrees,
        'institution_type': institution.type.lower()
    })

@app.route('/profile')
@login_required
def view_own_profile():
    institution_type = 'school'  
    if current_user.institution and current_user.institution.type:
        institution_type = current_user.institution.type.strip().lower()
    
    return render_template(
        'profile/view_profile.html',
        user=current_user,
        institution_type=institution_type
    )

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_own_profile():
    user = current_user
    
    institution = InstitutionDetails.query.get(user.institution_id)
    institution_type = institution.type.lower() if institution else 'school'

    
    class_options = []
    stream_options = []
    subject_options = []
    degree_options = []

    if institution:
        if institution.classes:
            class_options = [c.strip() for c in institution.classes.split(',')]
        if institution.streams:
            stream_options = [s.strip() for s in institution.streams.split(',')]
        if institution.degrees:
            degree_options = [d.strip() for d in institution.degrees.split(',')]

        
        teacher_subjects = db.session.query(TeacherClassAssignment.subject)\
            .join(User, TeacherClassAssignment.teacher_id == User.id)\
            .filter(User.institution_id == user.institution_id)\
            .distinct().all()
        subject_options = [sub[0] for sub in teacher_subjects]

    if request.method == 'POST':
        user.username = request.form['username']
        if request.form.get('password'):
            user.password = generate_password_hash(request.form['password'])

        if user.role == 'student':
            user.class_name = request.form.get('class_name', '')
            user.stream_or_semester = request.form.get('stream_or_semester', '')
            user.subject = ', '.join(request.form.getlist('subject'))  
            user.degree = request.form.get('degree', '')
            user.roll_number = request.form.get('roll_number', '').strip()
            if 'photo' in request.files:
                photo_file = request.files['photo']
                if photo_file and photo_file.filename != '':
                    filename = secure_filename(f"{user.id}_{photo_file.filename}")
                    upload_folder = os.path.join('static', 'uploads', 'photos')
                    os.makedirs(upload_folder, exist_ok=True)
                    filepath = os.path.join(upload_folder, filename)
                    photo_file.save(filepath)
                    
                    user.photo = os.path.join('uploads', 'photos', filename).replace('\\', '/')

        try:
            db.session.commit()
            flash('Profile updated successfully.', 'success')
            return redirect(url_for('view_own_profile'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while updating the profile.', 'danger')

    
    if user.role != 'student':
        return render_template('profile/edit_profile.html',
            user=user,
            institution_type=institution_type,
            class_options=[],
            stream_options=[],
            subject_options=[],
            degree_options=[]
        )

    return render_template('profile/edit_profile.html',
        user=user,
        institution_type=institution_type,
        class_options=class_options,
        stream_options=stream_options,
        subject_options=subject_options,
        degree_options=degree_options
    )

from fingerprint_device import enroll_and_download_template, FingerprintError, match_fingerprint
from models import Fingerprint 
from sqlalchemy.exc import SQLAlchemyError

@app.route('/api/fingerprint/enroll', methods=['POST'])
@login_required
def api_fingerprint_enroll():
    if not current_app.config.get('FINGERPRINT_ENABLE', True):
        return jsonify(success=False, error='Fingerprint feature is disabled by admin.'), 503

    if current_user.role != 'student':
        return jsonify(success=False, error='Only students can register fingerprint.'), 403

    try:
        position, template_bytes = enroll_and_download_template()

        fp = Fingerprint.query.filter_by(user_id=current_user.id).first()
        if not fp:
            fp = Fingerprint(user_id=current_user.id, sensor_position=position, template=template_bytes)
            db.session.add(fp)
        else:
            fp.sensor_position = position
            fp.template = template_bytes

        db.session.commit()

        return jsonify(
            success=True,
            message='Fingerprint registered successfully.',
            data={'sensor_position': position, 'user_id': current_user.id, 'username': current_user.username}
        ), 200

    except FingerprintError as fe:
        db.session.rollback()
        return jsonify(success=False, error=str(fe)), 400
    except SQLAlchemyError as se:
        db.session.rollback()
        return jsonify(success=False, error='Database error while saving template.'), 500
    except Exception as e:
        db.session.rollback()
        return jsonify(success=False, error='Unexpected error during enrollment.'), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


def role_required(role):
    def decorator(f):
        @login_required
        def decorated_function(*args, **kwargs):
            if current_user.role != role:
                flash('Access denied. Insufficient permissions.', 'error')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

class AttendanceAnalytics:
    def __init__(self, institution_id):
        self.institution_id = institution_id

    def get_admin_insights(self):
        
        total_students = User.query.filter_by(role='student', institution_id=self.institution_id).count()

        attendance_query = db.session.query(Attendance).join(
            User, Attendance.student_id == User.id
        ).filter(
            User.institution_id == self.institution_id,
            User.role == 'student'
        )

        total_attendance = attendance_query.count()
        present_count = attendance_query.filter(Attendance.status == 'Present').count()

        overall_percentage = round((present_count / total_attendance) * 100, 1) if total_attendance else 0

        
        students = User.query.filter_by(role='student', institution_id=self.institution_id).all()
        at_risk_students = []
        for student in students:
            student_att = db.session.query(Attendance).filter_by(student_id=student.id).all()
            total = len(student_att)
            if total == 0:
                continue  

            present = sum(1 for a in student_att if a.status == 'Present')
            percent = round((present / total) * 100, 1)

            if percent < 60:
                at_risk_students.append({
                    'student': student,
                    'current_percentage': percent,
                    'risk_score': 5 if percent < 40 else 3,
                    'trend': None  
                })

        
        subject_stats = {}
        subjects = db.session.query(Attendance.subject).join(User, Attendance.student_id == User.id).filter(
            User.institution_id == self.institution_id
        ).distinct()

        for subject_row in subjects:
            subject = subject_row.subject

            subj_att = db.session.query(Attendance).join(User, Attendance.student_id == User.id).filter(
                Attendance.subject == subject,
                User.institution_id == self.institution_id
            )

            total_classes = subj_att.count()
            total_present = subj_att.filter(Attendance.status == 'Present').count()
            attendance_rate = round((total_present / total_classes) * 100, 1) if total_classes else 0

            subject_stats[subject] = {
                'total_classes': total_classes,
                'attendance_rate': attendance_rate,
                'class_name': db.session.query(Attendance.class_name).filter_by(subject=subject).first()[0],
                'stream_or_semester': db.session.query(Attendance.stream_or_semester).filter_by(subject=subject).first()[0]
            }

        return {
            'overall_stats': {
                'total_students': total_students,
                'overall_percentage': overall_percentage
            },
            'at_risk_students': at_risk_students,
            'subject_stats': subject_stats
        }

    def get_teacher_insights(self, teacher_id, institution_type):
        total_attendance = Attendance.query.filter_by(teacher_id=teacher_id).count()
        present_count = Attendance.query.filter_by(teacher_id=teacher_id, status='Present').count()
        attendance_percentage = round((present_count / total_attendance) * 100, 1) if total_attendance else 0

        distinct_pairs = db.session.query(
            Attendance.class_name,
            Attendance.subject,
            Attendance.stream_or_semester,
            Attendance.degree
        ).filter_by(teacher_id=teacher_id).distinct().all()

        total_subjects = len(distinct_pairs)

        
        subject_performance = {}
        for class_name, subject, stream, degree in distinct_pairs:
            student_attendance = db.session.query(
                Attendance.student_id,
                func.count().label('total_classes'),
                func.sum(case((Attendance.status == 'Present', 1), else_=0)).label('present_classes')
            ).filter_by(
                teacher_id=teacher_id,
                subject=subject,
                class_name=class_name
            ).group_by(Attendance.student_id).all()

            total_students = len(student_attendance)
            if total_students == 0:
                continue

            total_percent = 0
            for entry in student_attendance:
                rate = round((entry.present_classes / entry.total_classes) * 100, 1) if entry.total_classes else 0
                total_percent += rate

            average_attendance = round(total_percent / total_students, 1)

            key_parts = [f"Class/Semester: {class_name}"]

            if institution_type == 'school':
                if class_name.startswith('11') or class_name.startswith('12'):
                    key_parts.append(f"Stream: {stream or '-'}")
            elif institution_type in ['college', 'university']:
                key_parts.extend([
                    f"Subject: {subject or '-'}",
                    f"Degree: {degree or '-'}"
                ])

            key = " | ".join(key_parts)
            subject_performance[key] = {
                'student_count': total_students,
                'average_attendance': average_attendance
            }

        
        at_risk_in_classes = self.get_at_risk_students(teacher_id)

        rows = db.session.query(
            Attendance.class_name,
            Attendance.subject,
            Attendance.stream_or_semester,
            Attendance.degree,
            func.count().label('total'),
            func.sum(case((Attendance.status == 'Present', 1), else_=0)).label('present')
        ).filter_by(teacher_id=teacher_id).group_by(
            Attendance.class_name,
            Attendance.subject,
            Attendance.stream_or_semester,
            Attendance.degree
        ).all()

        breakdown = {}
        for row in rows:
            key_parts = [row.class_name]

            if institution_type == 'school' and (row.class_name.startswith('11') or row.class_name.startswith('12')):
                key_parts.append(f"Stream: {row.stream_or_semester or '-'}")
            elif institution_type in ['college', 'university']:
                key_parts.extend([f"Subject: {row.subject}", f"Degree: {row.degree or '-'}"])
            else:
                key_parts.append(f"Subject: {row.subject}")

            key = " | ".join(key_parts)
            breakdown[key] = {
                'total_classes': row.total,
                'present_count': row.present,
                'attendance_rate': round((row.present / row.total) * 100, 1) if row.total else 0
            }

        return {
            'teacher_stats': {
                'total_marked': total_attendance,
                'present_marked': present_count,
                'attendance_percentage': attendance_percentage,
                'classes_taught': total_subjects  
            },
            'class_subject_breakdown': breakdown,
            'subject_performance': subject_performance,
            'at_risk_in_classes': at_risk_in_classes
        }

    def get_at_risk_students(self, teacher_id):
        students = db.session.query(User).filter_by(role='student', institution_id=self.institution_id).all()
        result = []

        for student in students:
            student_attendance = db.session.query(Attendance).filter_by(
                teacher_id=teacher_id,
                student_id=student.id
            ).all()

            total = len(student_attendance)
            present = len([att for att in student_attendance if att.status == 'Present'])
            percent = round((present / total) * 100, 1) if total > 0 else 0

            if percent < 60:
                for att in student_attendance:
                    subject = att.subject or next(
                        (a.subject for a in student_attendance if a.subject), None
                    )

                    result.append({
                        'student': student,
                        'class': student.class_name,
                        'subject': subject,
                        'percentage': percent
                    })
                    break

        return result

@app.route('/admin/dashboard')
@role_required('admin')
def admin_dashboard():
    institution = InstitutionDetails.query.filter_by(admin_id=current_user.id).first()
    if not institution:
        flash('No institution linked to your admin account.', 'error')
        return redirect(url_for('logout'))

    pending_users = User.query.filter_by(
        status='pending',
        institution_id=institution.id
    ).all()

    analytics = AttendanceAnalytics(institution_id=institution.id)
    insights = analytics.get_admin_insights()
    
    return render_template(
        'admin/dashboard.html',
        pending_users=pending_users,
        institution=institution,
        insights=insights,
        institution_type=institution.type.lower(),
        subject_stats=insights['subject_stats']
    )

@app.route('/admin/institution-setup', methods=['GET', 'POST'])
@role_required('admin')
def institution_setup():
    institution = InstitutionDetails.query.filter_by(admin_id=current_user.id).first()
    if request.method == 'POST':
        if institution:
            
            institution.name = request.form['name']
            institution.type = request.form['type']
            institution.country = request.form['country']
            institution.state = request.form['state']
            institution.city = request.form['city']
            institution.medium = request.form['medium']
            institution.classes = request.form['classes']
            institution.streams = request.form.get('streams', '')
            institution.degrees = request.form.get('degrees', '')
            institution.allowed_domain = request.form.get('allowed_domain', '').strip()
            institution.wifi_restriction_enabled = 'wifi_restriction_enabled' in request.form
        else:
            
            institution = InstitutionDetails(
                name=request.form['name'],
                type=request.form['type'],
                country=request.form['country'],
                state=request.form['state'],
                city=request.form['city'],
                medium=request.form['medium'],
                classes=request.form['classes'],
                streams=request.form.get('streams', ''),
                degrees=request.form.get('degrees', ''),
                allowed_domain=request.form.get('allowed_domain', '').strip(),
                wifi_restriction_enabled='wifi_restriction_enabled' in request.form
            )
            db.session.add(institution)

        db.session.commit()
        flash('Institution details saved successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/institution_setup.html', institution=institution)

@app.route('/admin/generate-pins', methods=['GET', 'POST'])
@role_required('admin')
def generate_pins():
    if request.method == 'POST':
        role = request.form['role']
        count = int(request.form['count'])

        institution_id = current_user.institution_id
        if not institution_id:
            flash('Your account is not linked to any institution.', 'error')
            return redirect(url_for('admin_dashboard'))

        pins = []
        for _ in range(count):
            pin_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            pin = Pin(pin_code=pin_code, role=role, institution_id=institution_id)
            db.session.add(pin)
            pins.append(pin_code)

        db.session.commit()
        flash(f'Generated {count} PINs for {role}s', 'success')
        return render_template('admin/generate_pins.html', generated_pins=pins)

    
    all_pins = Pin.query.filter_by(institution_id=current_user.institution_id).all()
    return render_template('admin/generate_pins.html', unused_pins=all_pins)

@app.route('/admin/approve-user/<int:user_id>', methods=['POST'])
@role_required('admin')
def approve_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.institution_id != current_user.institution_id:
        return jsonify({'error': 'Unauthorized'}), 403

    user.status = 'active'
    db.session.commit()
    return jsonify({'status': 'approved'})

@app.route('/admin/reject-user/<int:user_id>', methods=['POST'])
@role_required('admin')
def reject_user(user_id):
    user = User.query.get_or_404(user_id)

    if user.institution_id != current_user.institution_id:
        return jsonify({'error': 'Unauthorized'}), 403

    db.session.delete(user)
    db.session.commit()
    return jsonify({'status': 'rejected'})

@app.route('/admin/bulk-<action>-users', methods=['POST'])
@role_required('admin')
def bulk_user_action(action):
    data = request.get_json()
    user_ids = data.get('user_ids', [])

    for user_id in user_ids:
        user = User.query.get(user_id)
        if user and user.institution_id == current_user.institution_id:
            if action == 'approve':
                user.status = 'active'
            elif action == 'reject':
                db.session.delete(user)

    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/promotions', methods=['GET', 'POST'])
@role_required('admin')
def student_promotions():
    
    institution = InstitutionDetails.query.filter_by(admin_id=current_user.id).first()

    if not institution:
        flash("No institution found for current admin", "danger")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        student_ids = request.form.getlist('student_ids')
        new_class = request.form['new_class']
        new_stream = request.form.get('new_stream', '')

        for student_id in student_ids:
            student = User.query.filter_by(
                id=student_id,
                institution_id=institution.id,
                role='student'
            ).first()
            if student:
                log = PromotionLog(
                    student_id=student.id,
                    old_class=student.class_name,
                    new_class=new_class,
                    admin_id=current_user.id
                )
                db.session.add(log)
                student.class_name = new_class
                student.stream_or_semester = new_stream

        db.session.commit()
        flash(f'Promoted {len(student_ids)} students successfully!', 'success')

    
    students = User.query.filter_by(
        role='student',
        status='active',
        institution_id=institution.id
    ).all()

    
    class_options = []
    if institution.classes:
        class_options = [c.strip() for c in institution.classes.split(',')]

    
    stream_options = []
    if institution.streams:
        stream_options = [s.strip() for s in institution.streams.split(',')]

    return render_template('admin/promotions.html',
        students=students,
        class_options=class_options,
        stream_options=stream_options,
        institution_type=institution.type.lower()
    )

@app.route('/teacher/dashboard')
@role_required('teacher')
def teacher_dashboard():
    teacher = current_user
    teacher_institution_id = teacher.institution_id

    
    institution = InstitutionDetails.query.get(teacher_institution_id)
    institution_type = institution.type.lower() if institution else 'school'

    assignments = TeacherClassAssignment.query.filter_by(teacher_id=teacher.id).all()

    assigned_pairs = {
        (a.class_name.strip(), (a.stream_or_semester or '').strip()): a
        for a in assignments
    }

    
    all_pending = User.query.filter_by(
        role='student', status='pending', institution_id=teacher_institution_id
    ).all()
    pending_students = []

    for s in all_pending:
        student_class = (s.class_name or '').strip()
        student_stream = (s.stream_or_semester or '').strip()
        student_degree = (s.degree or '').strip()
        student_subjects = [sub.strip() for sub in (s.subject or '').split(',') if sub.strip()]

        for a in assignments:
            assign_class = (a.class_name or '').strip()
            assign_stream = (a.stream_or_semester or '').strip()
            assign_degree = (a.degree or '').strip()
            assign_subject = (a.subject or '').strip()

            if institution_type == 'school':
                if student_class == assign_class:
                    if student_class.startswith('11') or student_class.startswith('12'):
                        if student_stream == assign_stream:
                            pending_students.append(s)
                            break
                    else:
                        pending_students.append(s)
                        break

            elif institution_type in ['college', 'university']:
                if (
                    student_class == assign_class and
                    student_degree == assign_degree and
                    assign_subject and assign_subject in student_subjects
                ):
                    pending_students.append(s)
                    break

    ist = timezone('Asia/Kolkata')
    today = datetime.now(ist).date()
    attendance_today = db.session.query(
        Attendance.class_name, Attendance.subject
    ).filter_by(teacher_id=teacher.id, date=today).distinct().all()
    marked_today_pairs = {(cn, subj) for cn, subj in attendance_today}

    analytics = AttendanceAnalytics(institution_id=teacher_institution_id)
    insights = analytics.get_teacher_insights(teacher.id, institution_type)

    return render_template('teacher/dashboard.html',
        assignments=assignments,
        pending_students=pending_students,
        marked_today_pairs=marked_today_pairs,
        insights=insights,
        current_month_year=datetime.now().strftime('%B %Y'),
        institution_type=institution_type  
    )

@app.route('/teacher/parent-status')
@role_required('teacher')
def parent_status():
    try:
        teacher = current_user
        teacher_inst = teacher.institution

        if not teacher_inst:
            abort(403, "Institution not found for current teacher")

        teacher_inst_id = teacher.institution_id
        teacher_inst_type = teacher_inst.type.strip().lower()

        assigned_classes = TeacherClassAssignment.query.filter_by(teacher_id=teacher.id).all()

        students = User.query.filter_by(role='student', institution_id=teacher_inst_id).all()

        missing_parents = []

        for student in students:
            if not student.class_name:
                continue

            student_class = str(student.class_name).strip()
            student_stream = (student.stream_or_semester or '').strip().lower()
            student_degree = (student.degree or '').strip().lower()
            student_subjects = [s.strip().lower() for s in (student.subject or '').split(',') if s.strip()]
            student_inst_type = (student.institution.type or '').strip().lower()

            match_found = False

            for assignment in assigned_classes:
                if assignment.institution_id and assignment.institution_id != teacher_inst_id:
                    continue

                teacher_class = str(assignment.class_name or '').strip()
                teacher_stream = (assignment.stream_or_semester or '').strip().lower()
                teacher_subject = (assignment.subject or '').strip().lower()
                teacher_degree = (assignment.degree or '').strip().lower()

                if 'school' in [teacher_inst_type, student_inst_type]:
                    if student_class.startswith('11') or student_class.startswith('12'):
                        if (
                            student_class == teacher_class and
                            student_stream == teacher_stream
                        ):
                            match_found = True
                            break
                    else:
                        if student_class == teacher_class:
                            match_found = True
                            break

                elif teacher_inst_type != 'school' and student_inst_type != 'school':
                    if (
                        student_class == teacher_class and
                        student_degree == teacher_degree and
                        teacher_subject in student_subjects
                    ):
                        match_found = True
                        break

            if not match_found:
                continue

            parent = ParentContact.query.filter_by(student_id=student.id).first()
            if not parent or (not parent.email and not parent.phone):
                missing_parents.append(student)

        now = datetime.now()
        last_sent = teacher.last_parent_report_sent
        show_send_button = not last_sent or (last_sent.year != now.year or last_sent.month != now.month)

        return render_template(
            "teacher/parent_status.html",
            missing_parents=missing_parents,
            show_send_button=show_send_button,
            institution_type=teacher_inst_type
        )

    except Exception as e:
        abort(500, "An error occurred while processing parent status.")

@app.route('/delete-teacher/<int:teacher_id>', methods=['POST'])
@login_required
def delete_teacher(teacher_id):
    if current_user.role != 'admin':
        flash("Unauthorized access: Only admin can delete teachers.", "danger")
        return redirect(url_for('teacher_list'))

    teacher = User.query.filter_by(id=teacher_id, role='teacher').first()
    if not teacher:
        flash("Teacher not found or already deleted.", "warning")
        return redirect(url_for('teacher_list'))

    try:
        
        TeacherClassAssignment.query.filter_by(teacher_id=teacher_id).delete()

        
        Attendance.query.filter_by(teacher_id=teacher_id).delete()

        
        QRCodeSession.query.filter_by(teacher_id=teacher_id).delete()

        
        db.session.delete(teacher)
        db.session.commit()

        flash(f"Teacher '{teacher.username}' deleted successfully.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error while deleting teacher: {str(e)}", "danger")
        print(str(e))  

    return redirect(url_for('teacher_list'))

@app.route('/students/delete/<int:student_id>', methods=['POST'])
@login_required
def delete_student(student_id):
    if current_user.role not in ['admin', 'teacher']:
        abort(403)

    student = User.query.get_or_404(student_id)

    if student.role != 'student':
        flash('You can only delete students.', 'warning')
        return redirect(url_for('student_list'))

    try:
        
        Attendance.query.filter_by(student_id=student.id).delete()

        
        ParentContact.query.filter_by(student_id=student.id).delete()

        
        PromotionLog.query.filter_by(student_id=student.id).delete()

        
        db.session.delete(student)
        db.session.commit()

        flash('Student deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting student: {str(e)}', 'danger')

    return redirect(url_for('student_list'))

from utils import send_email_notification, send_whatsapp_message
from calendar import monthrange

@app.route('/teacher/send-custom-message', methods=['POST'])
@role_required('teacher')
def send_custom_message_to_parents():
    try:
        teacher = current_user
        subject = request.form.get('subject', '').strip()
        body = request.form.get('body', '').strip()

        if not subject or not body:
            flash("Subject and message body cannot be empty.", 'danger')
            return redirect(url_for('parent_status'))

        teacher_inst = teacher.institution
        if not teacher_inst:
            abort(403, "Institution not found for current teacher")

        inst_id = teacher.institution_id
        teacher_inst_type = teacher_inst.type.strip().lower()
        assignments = TeacherClassAssignment.query.filter_by(teacher_id=teacher.id).all()
        students = User.query.filter_by(role='student', institution_id=inst_id).all()

        sent_email_count = 0
        sent_whatsapp_count = 0

        for student in students:
            student_class = (student.class_name or '').strip()
            student_stream = (student.stream_or_semester or '').strip().lower()
            student_degree = (student.degree or '').strip().lower()
            student_subjects = [s.strip().lower() for s in (student.subject or '').split(',') if s.strip()]
            student_inst_type = (student.institution.type or '').strip().lower()

            match_found = False
            for a in assignments:
                if a.institution_id != inst_id:
                    continue

                if teacher_inst_type == 'school':
                    if student_class.startswith('11') or student_class.startswith('12'):
                        if student_class == a.class_name and student_stream == (a.stream_or_semester or '').strip().lower():
                            match_found = True
                            break
                    elif student_class == a.class_name:
                        match_found = True
                        break
                else:
                    if (
                        student_class == a.class_name and
                        student_degree == (a.degree or '').strip().lower() and
                        (a.subject or '').strip().lower() in student_subjects
                    ):
                        match_found = True
                        break

            if not match_found:
                continue

            parent = ParentContact.query.filter_by(student_id=student.id).first()
            if not parent:
                continue

            personalized_msg = f"Dear {parent.parent_name},\n\n{body}\n\nRegards,\n{teacher.username}"

            if parent.email and send_email_notification(to_email=parent.email, subject=subject, body=personalized_msg):
                sent_email_count += 1

            if parent.phone and send_whatsapp_message(parent.phone, personalized_msg):
                sent_whatsapp_count += 1

        flash(f"✅ Emails sent: {sent_email_count}, WhatsApp messages sent: {sent_whatsapp_count}.", "info")
        return redirect(url_for('parent_status'))

    except Exception as e:
        print("Error sending custom parent message:", str(e))
        abort(500, "An error occurred while sending the message.")

@app.route('/teacher/send-to-parents')
@role_required('teacher')
def send_attendance_to_parents():
    try:
        teacher = current_user
        teacher_inst = teacher.institution

        if not teacher_inst:
            abort(403, "Institution not found for current teacher")

        inst_id = teacher.institution_id
        teacher_inst_type = teacher_inst.type.strip().lower()

        today = date.today()
        year, month = today.year, today.month

        assignments = TeacherClassAssignment.query.filter_by(teacher_id=teacher.id).all()
        students = User.query.filter_by(role='student', institution_id=inst_id).all()

        sent_email_count = 0
        sent_whatsapp_count = 0
        missing_info = []

        for student in students:
            if not student.class_name:
                continue

            student_class = str(student.class_name).strip()
            student_stream = (student.stream_or_semester or '').strip().lower()
            student_degree = (student.degree or '').strip().lower()
            student_subjects = [s.strip().lower() for s in (student.subject or '').split(',') if s.strip()]
            student_inst_type = (student.institution.type or '').strip().lower()

            match_found = False

            for assignment in assignments:
                if assignment.institution_id and assignment.institution_id != inst_id:
                    continue

                teacher_class = str(assignment.class_name or '').strip()
                teacher_stream = (assignment.stream_or_semester or '').strip().lower()
                teacher_subject = (assignment.subject or '').strip().lower()
                teacher_degree = (assignment.degree or '').strip().lower()

                if 'school' in [teacher_inst_type, student_inst_type]:
                    if student_class.startswith('11') or student_class.startswith('12'):
                        if (
                            student_class == teacher_class and
                            student_stream == teacher_stream
                        ):
                            match_found = True
                            break
                    else:
                        if student_class == teacher_class:
                            match_found = True
                            break
                elif teacher_inst_type != 'school' and student_inst_type != 'school':
                    if (
                        student_class == teacher_class and
                        student_degree == teacher_degree and
                        teacher_subject in student_subjects
                    ):
                        match_found = True
                        break

            if not match_found:
                continue

            parent = ParentContact.query.filter_by(student_id=student.id).first()
            if not parent or (not parent.email and not parent.phone):
                missing_info.append(student)
                continue

            start_date = date(year, month, 1)
            end_date = date(year, month, monthrange(year, month)[1])

            records = Attendance.query.filter(
                Attendance.student_id == student.id,
                Attendance.date >= start_date,
                Attendance.date <= end_date
            ).all()

            total = len(records)
            present = sum(1 for r in records if r.status == 'Present')
            percentage = round((present / total) * 100, 1) if total > 0 else 0

            subject = f"Monthly Attendance Report - {student.username}"
            body = f"""Dear {parent.parent_name},

This is the monthly attendance report for {student.username}.

Total Classes: {total}
Present: {present}
Attendance Percentage: {percentage}%

Thank you for your attention to your child's education.

Regards,
{teacher.username}
"""

            if parent.email and send_email_notification(to_email=parent.email, subject=subject, body=body):
                sent_email_count += 1

            if parent.phone and send_whatsapp_message(parent.phone, body):
                sent_whatsapp_count += 1

        teacher.last_parent_report_sent = datetime.utcnow()
        db.session.commit()

        msg = f"✅ Emails sent: {sent_email_count}, WhatsApp messages sent: {sent_whatsapp_count}."
        if missing_info:
            missing_names = ', '.join(s.username for s in missing_info)
            msg += f" ⚠️ Missing contact info for: {missing_names}"

        flash(msg, 'info')
        return redirect(url_for('teacher_dashboard'))

    except Exception as e:
        abort(500, "An error occurred while sending attendance reports.")

@app.route('/teacher/send-missing-info-reminder')
@role_required('teacher')
def send_missing_info_reminder():
    try:
        teacher = current_user
        teacher_inst = teacher.institution

        if not teacher_inst:
            abort(403, "Institution not found for current teacher")

        teacher_inst_id = teacher.institution_id
        teacher_inst_type = teacher_inst.type.strip().lower()

        assigned_classes = TeacherClassAssignment.query.filter_by(teacher_id=teacher.id).all()

        students = User.query.filter_by(role='student', institution_id=teacher_inst_id).all()

        missing_students = []
        reminders_sent = 0

        for student in students:
            if not student.class_name:
                continue

            student_class = str(student.class_name).strip()
            student_stream = (student.stream_or_semester or '').strip().lower()
            student_degree = (student.degree or '').strip().lower()
            student_subjects = [s.strip().lower() for s in (student.subject or '').split(',') if s.strip()]
            student_inst_type = (student.institution.type or '').strip().lower()

            match_found = False

            for assignment in assigned_classes:
                if assignment.institution_id and assignment.institution_id != teacher_inst_id:
                    continue

                teacher_class = str(assignment.class_name or '').strip()
                teacher_stream = (assignment.stream_or_semester or '').strip().lower()
                teacher_subject = (assignment.subject or '').strip().lower()
                teacher_degree = (assignment.degree or '').strip().lower()

                if 'school' in [teacher_inst_type, student_inst_type]:
                    if student_class.startswith('11') or student_class.startswith('12'):
                        if (
                            student_class == teacher_class and
                            student_stream == teacher_stream
                        ):
                            match_found = True
                            break
                    else:
                        if student_class == teacher_class:
                            match_found = True
                            break
                elif teacher_inst_type != 'school' and student_inst_type != 'school':
                    if (
                        student_class == teacher_class and
                        student_degree == teacher_degree and
                        teacher_subject in student_subjects
                    ):
                        match_found = True
                        break

            if not match_found:
                continue

            parent = ParentContact.query.filter_by(student_id=student.id).first()
            if not parent or (not parent.email and not parent.phone):
                missing_students.append(student)

        for student in missing_students:
            subject = "Reminder: Provide Parent Contact Details"
            body = f"""Dear {student.username},

Our records show that your parent/guardian's contact information is missing.

Please update your profile with valid email and phone number for your parent/guardian as soon as possible.

This is required to ensure important updates regarding your progress can be shared.

Regards,  
{teacher.username}
"""

            if student.email and send_email_notification(to_email=student.email, subject=subject, body=body):
                reminders_sent += 1

        db.session.commit()

        flash(f"📢 Sent reminder to {reminders_sent} student(s) to update parent contact info.", "info")
        return redirect(url_for('teacher_dashboard'))

    except Exception as e:
        abort(500, "An error occurred while sending reminders.")

@app.route('/get-teacher-options', methods=['POST'])
def get_teacher_options():
    data = request.get_json()
    pin_code = data.get('pin')
    role = data.get('role')

    if role != 'teacher':
        return jsonify({'error': 'Only teachers access this'}), 400

    pin = Pin.query.filter_by(pin_code=pin_code, role='teacher').first()
    if not pin:
        return jsonify({'error': 'Invalid PIN'}), 400

    inst = InstitutionDetails.query.get(pin.institution_id)
    if not inst:
        return jsonify({'error': 'Institution not found'}), 404

    result = {}
    if inst.classes:
        result['classes'] = [c.strip() for c in inst.classes.split(',')]
    if inst.streams:
        result['streams'] = [s.strip() for s in inst.streams.split(',')]
    if inst.degrees:
        result['degrees'] = [d.strip() for d in inst.degrees.split(',')]

    return jsonify(result)

@app.route('/teacher/assign-classes', methods=['GET', 'POST'])
@role_required('teacher')
def assign_classes():
    edit_id = request.args.get('edit')
    delete_id = request.args.get('delete')

    
    if delete_id:
        assignment = TeacherClassAssignment.query.get_or_404(delete_id)
        if assignment.teacher_id == current_user.id:
            db.session.delete(assignment)
            db.session.commit()
            flash('Assignment deleted!', 'success')
        return redirect(url_for('assign_classes'))

    
    assignment_to_edit = None
    if edit_id:
        assignment_to_edit = TeacherClassAssignment.query.get_or_404(edit_id)
        if assignment_to_edit.teacher_id != current_user.id:
            flash('Unauthorized access to edit!', 'danger')
            return redirect(url_for('assign_classes'))

    if request.method == 'POST':
        class_name = request.form.get('class_name')
        subject = request.form.get('subject')
        stream = request.form.get('stream_or_semester', '')
        degree = request.form.get('degree', '')

        if request.form.get('edit_id'):  
            edit_obj = TeacherClassAssignment.query.get_or_404(request.form['edit_id'])
            if edit_obj.teacher_id == current_user.id:
                institution = InstitutionDetails.query.get(current_user.institution_id)

                
                if institution and institution.type.lower() == 'school':
                    if class_name.startswith('11') or class_name.startswith('12') and stream:
                        conflict = TeacherClassAssignment.query.filter(
                            TeacherClassAssignment.class_name == class_name,
                            TeacherClassAssignment.stream_or_semester == stream,
                            TeacherClassAssignment.id != edit_obj.id  
                        ).first()
                        if conflict:
                            flash(f"Class {class_name} with stream '{stream}' is already assigned to another teacher.", 'warning')
                            return redirect(url_for('assign_classes'))
                    else:
                        conflict = TeacherClassAssignment.query.filter(
                            TeacherClassAssignment.class_name == class_name,
                            TeacherClassAssignment.id != edit_obj.id
                        ).first()
                        if conflict:
                            flash(f"Class {class_name} is already assigned to another teacher.", 'warning')
                            return redirect(url_for('assign_classes'))
                else:
                    conflict = TeacherClassAssignment.query.filter(
                        TeacherClassAssignment.teacher_id == current_user.id,
                        TeacherClassAssignment.class_name == class_name,
                        TeacherClassAssignment.subject == subject,
                        TeacherClassAssignment.stream_or_semester == stream,
                        TeacherClassAssignment.degree == degree,
                        TeacherClassAssignment.id != edit_obj.id
                    ).first()
                    if conflict:
                        flash('You have already assigned this class+subject+degree.', 'warning')
                        return redirect(url_for('assign_classes'))

                edit_obj.class_name = class_name
                edit_obj.subject = subject
                edit_obj.stream_or_semester = stream
                edit_obj.degree = degree
                db.session.commit()
                flash('Assignment updated!', 'success')
                return redirect(url_for('assign_classes'))
        else:  
            institution = InstitutionDetails.query.get(current_user.institution_id)

            if institution and institution.type.lower() == 'school':
                if class_name.startswith('11') or class_name.startswith('12') and stream:
                    
                    existing = TeacherClassAssignment.query.filter_by(
                        class_name=class_name,
                        stream_or_semester=stream,
                        institution_id=current_user.institution_id
                    ).first()
                    if existing:
                        flash(f"Class {class_name} with stream '{stream}' is already assigned to another teacher.", 'warning')
                        return redirect(url_for('assign_classes'))
                else:
                    
                    existing = TeacherClassAssignment.query.filter_by(
                        class_name=class_name,
                        institution_id=current_user.institution_id
                    ).first()
                    if existing:
                        flash(f"Class {class_name} is already assigned to another teacher.", 'warning')
                        return redirect(url_for('assign_classes'))
            else:
                
                existing = TeacherClassAssignment.query.filter_by(
                    teacher_id=current_user.id,
                    class_name=class_name,
                    subject=subject,
                    stream_or_semester=stream,
                    degree=degree
                ).first()
                if existing:
                    flash('You have already assigned this class+subject+degree.', 'warning')
                    return redirect(url_for('assign_classes'))

            if existing:
                flash('Already assigned this class+subject', 'warning')
            else:
                db.session.add(TeacherClassAssignment(
                    teacher_id=current_user.id,
                    institution_id=current_user.institution_id,
                    class_name=class_name,
                    subject=subject,
                    stream_or_semester=stream,
                    degree=degree
                ))
                db.session.commit()
                flash('Class assigned!', 'success')

    
    institution = InstitutionDetails.query.get(current_user.institution_id)
    assignments = TeacherClassAssignment.query.filter_by(teacher_id=current_user.id).all()
    pin = Pin.query.filter_by(role='teacher', institution_id=current_user.institution_id).first()

    classes = [c.strip() for c in institution.classes.split(',')] if institution.classes else []
    streams = [s.strip() for s in institution.streams.split(',')] if institution.streams else []
    degrees = [d.strip() for d in institution.degrees.split(',')] if institution.degrees else []

    all_subjects = sorted(set(
        s[0] for s in db.session.query(TeacherClassAssignment.subject)
        .filter(TeacherClassAssignment.subject != None)
        .distinct()
        .all()
    ))
    return render_template('teacher/assign_classes.html',
        assignments=assignments,
        classes=classes,
        streams=streams,
        degrees=degrees,
        assignment_to_edit=assignment_to_edit,
        institution_type=institution.type.lower() if institution else 'school',
        teacher_pin=pin.pin_code if pin else '',
    all_subjects=all_subjects
    )

@app.route('/teacher/approve-student/<int:student_id>', methods=['POST'])
@role_required('teacher')
def approve_student_ajax(student_id):
    student = User.query.get_or_404(student_id)

    if student.institution_id != current_user.institution_id:
        return jsonify({'error': 'Unauthorized'}), 403

    student.status = 'active'
    db.session.commit()
    return jsonify({'status': 'approved'})

@app.route('/teacher/reject-student/<int:student_id>', methods=['POST'])
@role_required('teacher')
def reject_student_ajax(student_id):
    student = User.query.get_or_404(student_id)

    if student.institution_id != current_user.institution_id:
        return jsonify({'error': 'Unauthorized'}), 403

    db.session.delete(student)
    db.session.commit()
    return jsonify({'status': 'rejected'})

@app.route('/teacher/bulk-<action>-students', methods=['POST'])
@role_required('teacher')
def bulk_teacher_student_action(action):
    data = request.get_json()
    student_ids = data.get('student_ids', [])

    for student_id in student_ids:
        student = User.query.get(student_id)
        if student and student.institution_id == current_user.institution_id:
            if action == 'approve':
                student.status = 'active'
            elif action == 'reject':
                db.session.delete(student)

    db.session.commit()
    return jsonify({'success': True})

from pytz import timezone

@app.route('/teacher/attendance', methods=['GET', 'POST'])
@role_required('teacher')
def mark_attendance():
    institution = InstitutionDetails.query.get(current_user.institution_id)
    institution_type = institution.type.lower() if institution else 'school'

    error = None

    if request.method == 'POST':
        class_name = request.form.get('class_name', '').strip()
        subject = request.form.get('subject', '').strip()
        stream_or_semester = request.form.get('stream_or_semester', '').strip()
        degree = request.form.get('degree', '').strip()
        date_str = request.form.get('date', '').strip()

        
        if not class_name:
            error = "Class/Semester is required."
        elif institution_type == 'school':
            if (class_name.startswith('11') or class_name.startswith('12')) and not stream_or_semester:
                error = "Stream is required for class 11/12."
        elif institution_type in ['college', 'university']:
            if not subject:
                error = "Subject is required."
            if not degree:
                error = "Degree is required."
        if not date_str:
            error = "Date is required."

        if error:
            flash(error, 'danger')
        else:
            
            ist = timezone('Asia/Kolkata')
            try:
                date = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
                date = ist.localize(date)
            except Exception:
                flash('Invalid date format.', 'danger')
                return redirect(request.url)

            filtered_ids_raw = request.form.get('filtered_student_ids')
            try:
                filtered_ids = json.loads(filtered_ids_raw)
            except Exception:
                filtered_ids = []

            students = User.query.filter(
                User.id.in_(filtered_ids),
                User.role == 'student',
                User.status == 'active',
                User.institution_id == current_user.institution_id
            ).all()

            if institution_type == 'school' and (class_name.startswith('11') or class_name.startswith('12')):
                students = [s for s in students if s.stream_or_semester == stream_or_semester and s.class_name == class_name]

            elif institution_type in ['college', 'university']:
                students = [s for s in students if (
                    s.class_name == class_name and
                    s.degree == degree and
                    subject.lower() in (s.subject or '').lower()
                )]

            for student in students:
                status = request.form.get(f'attendance_{student.id}', 'Absent')
                existing = Attendance.query.filter(
                    Attendance.student_id == student.id,
                    Attendance.teacher_id == current_user.id,  
                    Attendance.subject == subject if institution_type in ['college', 'university'] else True,
                    Attendance.degree == degree if institution_type in ['college', 'university'] else True,
                    func.date(Attendance.date) == date.date()
                ).first()
                if not existing:
                    attendance = Attendance(
                        student_id=student.id,
                        teacher_id=current_user.id,
                        class_name=class_name,
                        subject=subject,
                        stream_or_semester=stream_or_semester if institution_type == 'school' and (class_name.startswith('11') or class_name.startswith('12')) else '',
                        degree=degree if institution_type in ['college', 'university'] else '',
                        date=date,
                        status=status,
                        method='manual',
                        institution_id=current_user.institution_id,
                        roll_number=student.roll_number
                    )
                    db.session.add(attendance)
                    if status == 'Absent':
                        print(f"NOTIFICATION: {student.username} was absent on {date} for {subject}")

                        parent = ParentContact.query.filter_by(student_id=student.id).first()
                        if parent:
                            message_body = f"""
Dear {parent.parent_name},

This is to inform you that your child, {student.username}, was marked *Absent* today.

Details:
• Class/Semester: {class_name}
• Subject: {subject if institution_type != 'school' else 'N/A'}
• Date: {date.strftime('%d-%m-%Y %I:%M %p')}
• Degree: {degree if institution_type != 'school' else 'N/A'}
• Stream: {stream_or_semester if institution_type == 'school' and (class_name.startswith('11') or class_name.startswith('12')) else 'N/A'}

Regards,
{current_user.username}
        """.strip()

                            if parent.email:
                                send_email_notification(to_email=parent.email, subject=f"Absence Notification - {student.username}", body=message_body)

                            if parent.phone:
                                send_whatsapp_message(parent.phone, message_body)

            db.session.commit()
            flash('Attendance marked successfully!', 'success')
            return redirect(request.url)

    assignments = TeacherClassAssignment.query.filter_by(teacher_id=current_user.id).all()
    return render_template('teacher/attendance.html',
        assignments=assignments,
        institution_type=institution_type
    )

from sqlalchemy import and_, func, case

@app.route('/api/get-students', methods=['POST'])
@role_required('teacher')
def get_students_by_class():
    data = request.get_json()
    class_name = data.get('class_name')
    date_str = data.get('date')
    stream_or_semester = data.get('stream_or_semester', '')
    degree = data.get('degree', '')
    subject = data.get('subject', '').strip()

    institution = InstitutionDetails.query.get(current_user.institution_id)

    if not class_name or not date_str:
        return jsonify({'error': 'Class/Semester name and date are required'}), 400

    
    ist = timezone('Asia/Kolkata')
    full_dt = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
    full_dt = ist.localize(full_dt)
    current_date_only = full_dt.date()

    subject = data.get('subject', '').strip()

    
    if institution and institution.type.lower() in ['college', 'university']:
        subquery = db.session.query(Attendance.student_id).filter(
            and_(
                Attendance.class_name == class_name,
                Attendance.subject == subject,
                Attendance.degree == degree,
                Attendance.teacher_id == current_user.id,  
                func.date(Attendance.date) == current_date_only
            )
        ).subquery()
    else:
        
        subquery = db.session.query(Attendance.student_id).filter(
            and_(
                Attendance.class_name == class_name,
                func.date(Attendance.date) == current_date_only
            )
        ).subquery()

    
    students = User.query.filter(
        User.role == 'student',
        User.status == 'active',
        User.class_name == class_name,
        User.institution_id == current_user.institution_id  
    )

    
    institution = InstitutionDetails.query.get(current_user.institution_id)
    
    if institution and institution.type.lower() == 'school':
        if (class_name.startswith('11') or class_name.startswith('12')) and stream_or_semester:
            students = students.filter(
                User.stream_or_semester == stream_or_semester,
                User.institution_id == current_user.institution_id,
                User.class_name == class_name
            )
    
    elif institution and institution.type.lower() in ['college', 'university']:
        if degree and class_name and data.get('subject'):
            subject = data['subject']
            students = students.filter(
                User.degree == degree,
                User.class_name == class_name,
                User.institution_id == current_user.institution_id,
                User.subject.ilike(f'%{subject}%')  
            )
        else:
            return jsonify({'error': 'Degree, class, and subject are required for colleges'}), 400

    students = students.filter(~User.id.in_(subquery)).all()

    student_list = [{'id': s.id, 'name': s.username, 'roll_number': s.roll_number} for s in students]
    return jsonify({'students': student_list})

@app.route('/teacher/generate-qr', methods=['GET', 'POST'])
@role_required('teacher')
def generate_qr():
    institution = InstitutionDetails.query.get(current_user.institution_id)
    institution_type = institution.type.lower() if institution else 'school'
    wifi_restriction_allowed = institution.wifi_restriction_enabled if institution else False
    teacher_ip = request.headers.get('X-Forwarded-For') or request.remote_addr
    if request.method == 'GET':
        persistent_qr = PersistentQRCode.query.filter_by(
            teacher_id=current_user.id,
            active=True
        ).first()

        rotating_qr = RotatingQRCode.query.filter(
            RotatingQRCode.teacher_id == current_user.id,
            RotatingQRCode.created_at >= datetime.utcnow() - timedelta(seconds=2)
        ).first()

        if not persistent_qr and not rotating_qr:
            flash("You must generate a QR first before accessing this page.", "warning")
            return redirect(url_for('qr_method_selector'))

    print(f"[QR GENERATE] Teacher IP: {teacher_ip}")
    if request.method == 'POST':

        class_name = request.form['class_name']
        subject = request.form.get('subject', '')
        stream = request.form.get('stream_or_semester', '')
        degree = request.form.get('degree', '')
        mode = request.form.get('mode', 'qr')
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
        wifi_restriction = wifi_restriction_allowed and ('wifi_restriction' in request.form)
        current_user.allowed_ip = request.headers.get('X-Forwarded-For') or request.remote_addr
        qr_session = QRCodeSession(
            token=token,
            class_name=class_name,
            subject=subject,
            stream_or_semester=stream,
            degree=degree,
            teacher_id=current_user.id,
            institution_id=current_user.institution_id,
            expires_at=datetime.now() + timedelta(minutes=15),
            mode=mode,
            wifi_restriction=wifi_restriction,
            teacher_ip=teacher_ip if wifi_restriction else None
        )
        db.session.add(qr_session)
        db.session.commit()

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(token)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_code_data = base64.b64encode(buf.getvalue()).decode()

        if mode == 'qr':
            return render_template('teacher/qr_generated.html',
                                qr_code=qr_code_data,
                                token=token,
                                class_name=class_name,
                                subject=subject,
                                stream=stream,
                                degree=degree,
                                institution_type=institution_type)
        elif mode == 'biometric':
            return render_template('teacher/biometric_generated.html',
                                token=token,
                                class_name=class_name,
                                subject=subject,
                                stream=stream,
                                degree=degree,
                                expires_at=qr_session.expires_at,
                                institution_type=institution_type)

        elif mode == 'fingerprint':
            return redirect(url_for('fingerprint_session', session_id=qr_session.id))
    
    print("Student allowed IP:", current_user.allowed_ip)
    assignments = TeacherClassAssignment.query.filter_by(teacher_id=current_user.id).all()
    return render_template('teacher/generate_qr.html',
                           assignments=assignments,
                           institution_type=institution_type, wifi_restriction_allowed=wifi_restriction_allowed)

@app.route('/teacher/fingerprint-session/<int:session_id>', methods=['GET', 'POST'])
@role_required('teacher')
def fingerprint_session(session_id):
    qr_session = QRCodeSession.query.get_or_404(session_id)

    if request.method == 'POST':
        try:
            students = User.query.filter_by(
                institution_id=current_user.institution_id,
                role='student'
            ).all()

            matched_student = None

            for student in students:
                if student.fingerprint and match_fingerprint(student.fingerprint.template):
                    matched_student = student
                    break

            if not matched_student:
                return jsonify(success=False, error="No fingerprint matched.")

            institution = InstitutionDetails.query.get(matched_student.institution_id)
            institution_type = institution.type.lower() if institution else 'school'

            if matched_student.class_name != qr_session.class_name:
                return jsonify(success=False, error="Class does not match.")

            if institution_type == 'school':
                if matched_student.class_name.startswith('11') or matched_student.class_name.startswith('12'):
                    if matched_student.stream_or_semester != qr_session.stream_or_semester:
                        return jsonify(success=False, error="Stream does not match for your class!")
            elif institution_type in ['college', 'university']:
                if matched_student.degree != qr_session.degree:
                    return jsonify(success=False, error="Degree does not match!")
                student_subjects = [s.strip().lower() for s in (matched_student.subject or '').split(',')]
                qr_subject = (qr_session.subject or '').strip().lower()
                if qr_subject not in student_subjects:
                    return jsonify(success=False, error="Subject does not match your enrolled subjects!")

            today = datetime.utcnow().date()

            if institution_type in ['college', 'university']:
                existing = Attendance.query.filter(
                    Attendance.student_id == matched_student.id,
                    Attendance.teacher_id == qr_session.teacher_id,
                    Attendance.subject == qr_session.subject,
                    Attendance.degree == qr_session.degree,
                    func.date(Attendance.date) == today
                ).first()
            else:
                existing = Attendance.query.filter(
                    Attendance.student_id == matched_student.id,
                    func.date(Attendance.date) == today
                ).first()

            if existing:
                return jsonify(success=False, error="Attendance already marked today.")

            attendance = Attendance(
                student_id=matched_student.id,
                teacher_id=qr_session.teacher_id,
                class_name=qr_session.class_name,
                subject=qr_session.subject,
                stream_or_semester=matched_student.stream_or_semester or '',
                degree=matched_student.degree or '',
                institution_id=matched_student.institution_id,
                date=today,
                status='Present',
                method='Fingerprint',
                roll_number=matched_student.roll_number,
            )
            db.session.add(attendance)
            db.session.commit()

            return jsonify(success=True, student_name=matched_student.username)

        except Exception as e:
            return jsonify(success=False, error=str(e))

    return render_template('teacher/fingerprint_session.html', session=qr_session)

@app.route('/teacher/qr-method', methods=['GET'])
@role_required('teacher')
def qr_method_selector():
    return render_template('teacher/qr_method_selector.html')

@app.route('/teacher/qr-persistent', methods=['GET', 'POST'])
@role_required('teacher')
def qr_persistent():
    existing = PersistentQRCode.query.filter_by(teacher_id=current_user.id, active=True).first()
    if request.method == 'POST':
        if existing:
            db.session.delete(existing)
            db.session.commit()
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
        new_qr = PersistentQRCode(token=token, teacher_id=current_user.id)
        db.session.add(new_qr)
        db.session.commit()
        return redirect(url_for('qr_persistent'))

    return render_template('teacher/qr_persistent.html', qr=existing)

@app.route('/teacher/qr-rotating')
@role_required('teacher')
def qr_rotating():
    return render_template('teacher/qr_rotating.html')

@app.route('/teacher/qr-rotating-token')
@role_required('teacher')
def get_rotating_token():
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=25))
    db.session.add(RotatingQRCode(token=token, teacher_id=current_user.id))
    db.session.commit()
    return jsonify({'token': token})

@app.route('/qr/<token>')
def handle_qr_scan(token):
    persistent = PersistentQRCode.query.filter_by(token=token, active=True).first()
    rotating = RotatingQRCode.query.filter_by(token=token).order_by(RotatingQRCode.created_at.desc()).first()

    if persistent:
        return redirect(url_for('attendance_mark', token=token))
    elif rotating and datetime.utcnow() - rotating.created_at <= timedelta(seconds=1):
        return redirect(url_for('attendance_mark', token=token))
    else:
        return "❌ Invalid or expired QR code.", 400

@app.route('/get-attendance-filter-options', methods=['POST'])
@login_required
def get_attendance_filter_options():
    institution = InstitutionDetails.query.get(current_user.institution_id)
    if not institution:
        return jsonify({'error': 'Institution not found'}), 404

    
    classes = [cls.strip() for cls in institution.classes.split(',')] if institution.classes else []
    streams = [s.strip() for s in institution.streams.split(',')] if institution.streams else []
    degrees = [d.strip() for d in institution.degrees.split(',')] if institution.degrees else []

    
    teacher_ids = db.session.query(User.id).filter_by(role='teacher', institution_id=institution.id).subquery()
    assignments = TeacherClassAssignment.query.filter(
        TeacherClassAssignment.teacher_id.in_(teacher_ids)
    ).all()
    subjects = sorted({a.subject for a in assignments if a.subject})

    return jsonify({
        'classes': classes,
        'streams': streams,
        'subjects': subjects,
        'degrees': degrees,
        'institution_type': institution.type.lower()
    })

@app.route('/attendance-records', methods=['GET', 'POST'])
@login_required
def attendance_records():
    institution = InstitutionDetails.query.get(current_user.institution_id)
    institution_type = institution.type.lower() if institution else 'school'

    
    selected_class = request.form.get('class_name') or ''
    selected_subject = request.form.get('subject') or ''
    selected_stream = request.form.get('stream_or_semester') or ''
    selected_degree = request.form.get('degree') or ''
    selected_date = request.form.get('date') or ''

    
    filters = {'institution_id': current_user.institution_id}
    if selected_class:
        filters['class_name'] = selected_class
    if selected_subject:
        filters['subject'] = selected_subject
    if selected_stream:
        filters['stream_or_semester'] = selected_stream
    if selected_degree:
        filters['degree'] = selected_degree
    if selected_date:
        filters['date'] = datetime.strptime(selected_date, '%Y-%m-%d').date()

    
    try:
        data = Attendance.detailed_report(**filters)
    except Exception as e:
        flash(f"Error loading data: {e}", "danger")
        data = []

    
    classes = [c.strip() for c in (institution.classes or '').split(',') if c.strip()]
    streams = [s.strip() for s in (institution.streams or '').split(',') if s.strip()]
    degrees = [d.strip() for d in (institution.degrees or '').split(',') if d.strip()]
    
    subjects = sorted({a.subject for a in TeacherClassAssignment.query
                      .join(User, TeacherClassAssignment.teacher_id == User.id)
                      .filter(User.institution_id == current_user.institution_id)
                      .all() if a.subject})

    return render_template('attendance_records.html',
        data=data,
        classes=classes,
        streams=streams,
        degrees=degrees,
        subjects=subjects,
        institution_type=institution_type,
        selected_class=selected_class,
        selected_subject=selected_subject,
        selected_stream=selected_stream,
        selected_degree=selected_degree,
        selected_date=selected_date
    )

@app.route('/students-in-class', methods=['GET', 'POST'])
@login_required
def students_in_class():
    institution = InstitutionDetails.query.get(current_user.institution_id)
    institution_type = institution.type.lower() if institution else 'school'

    
    classes = [c.strip() for c in (institution.classes or '').split(',') if c.strip()]
    streams = [s.strip() for s in (institution.streams or '').split(',') if s.strip()]
    degrees = [d.strip() for d in (institution.degrees or '').split(',') if d.strip()]
    
    subjects = sorted({a.subject for a in TeacherClassAssignment.query
                      .join(User, TeacherClassAssignment.teacher_id == User.id)
                      .filter(User.institution_id == current_user.institution_id)
                      .all() if a.subject})

    
    selected_class = request.form.get('class_name') or ''
    selected_stream = request.form.get('stream_or_semester') or ''
    selected_subject = request.form.get('subject') or ''
    selected_degree = request.form.get('degree') or ''
    selected_student = request.form.get('student') or ''

    
    students_query = User.query.filter_by(role='student', institution_id=current_user.institution_id)
    if selected_class:
        students_query = students_query.filter_by(class_name=selected_class)
    if institution_type == 'school' and (selected_class.startswith('11') or selected_class.startswith('12')) and selected_stream:
        students_query = students_query.filter_by(stream_or_semester=selected_stream)
    if institution_type in ['college', 'university']:
        if selected_subject:
            students_query = students_query.filter(User.subject.ilike(f"%{selected_subject}%"))
        if selected_degree:
            students_query = students_query.filter_by(degree=selected_degree)
    students = students_query.all()

    
    students_with_stats = []
    for student in students:
        attendance_records = Attendance.query.filter_by(student_id=student.id).all()
        total = len(attendance_records)
        present = len([a for a in attendance_records if a.status == 'Present'])
        absent = total - present
        percentage = round((present / total * 100), 2) if total > 0 else 0
        students_with_stats.append({
            'student': student,
            'total': total,
            'present': present,
            'absent': absent,
            'percentage': percentage
        })

    
    student_detail = None
    student_detail_stats = None
    if selected_student:
        student_detail = User.query.get(int(selected_student))
        if student_detail:
            attendance_records = Attendance.query.filter_by(student_id=student_detail.id).all()
            total = len(attendance_records)
            present = len([a for a in attendance_records if a.status == 'Present'])
            absent = total - present
            percentage = round((present / total * 100), 2) if total > 0 else 0
            student_detail_stats = {
                'total': total,
                'present': present,
                'absent': absent,
                'percentage': percentage
            }

    return render_template('students_in_class.html',
        classes=classes,
        streams=streams,
        degrees=degrees,
        subjects=subjects,
        students=students_with_stats,
        institution_type=institution_type,
        selected_class=selected_class,
        selected_stream=selected_stream,
        selected_subject=selected_subject,
        selected_degree=selected_degree,
        selected_student=selected_student,
        student_detail=student_detail,
        student_detail_stats=student_detail_stats
    )

@app.route('/student/dashboard')
@role_required('student')
def student_dashboard():
    student = current_user

    attendance_records = Attendance.query.filter_by(student_id=student.id).order_by(Attendance.date.desc()).limit(30).all()

    total_classes = len(attendance_records)
    present_count = len([a for a in attendance_records if a.status == 'Present'])
    attendance_percentage = (present_count / total_classes * 100) if total_classes > 0 else 0

    parent_contact = ParentContact.query.filter_by(student_id=student.id).first()

    institution = InstitutionDetails.query.get(student.institution_id)
    institution_type = institution.type.lower() if institution else 'school'

    return render_template('student/dashboard.html',
                           attendance_records=attendance_records,
                           total_classes=total_classes,
                           present_count=present_count,
                           attendance_percentage=attendance_percentage,
                           parent_contact=parent_contact,
                           institution_type=institution_type,
                           student=student)

@app.route('/student/scan-entry', methods=['GET', 'POST'])
@role_required('student')
def scan_entry():
    if request.method == 'POST':
        token = request.form.get('token', '').strip()

        persistent = PersistentQRCode.query.filter_by(token=token, active=True).first()
        rotating = RotatingQRCode.query.filter_by(token=token).order_by(RotatingQRCode.created_at.desc()).first()

        if persistent:
            session['scan_verified_at'] = datetime.utcnow().isoformat()
            session['scan_type'] = 'persistent'
            return redirect(url_for('scan_mode_selector'))

        elif rotating and datetime.utcnow() - rotating.created_at <= timedelta(seconds=1):
            session['scan_verified_at'] = datetime.utcnow().isoformat()
            session['scan_type'] = 'rotating'
            return redirect(url_for('scan_mode_selector'))

        flash('Invalid or expired QR code.', 'danger')
        return redirect(url_for('scan_entry'))

    return render_template('student/scan_entry.html')

@app.route('/student/scan-mode')
@role_required('student')
def scan_mode_selector():
    scan_time_str = session.get('scan_verified_at')
    if not scan_time_str:
        flash("You must scan a valid QR before proceeding.", "warning")
        return redirect(url_for('scan_entry'))

    scan_time = datetime.fromisoformat(scan_time_str)
    if datetime.utcnow() - scan_time > timedelta(minutes=15):
        session.pop('scan_verified_at', None)
        flash("QR session expired. Please scan again.", "warning")
        return redirect(url_for('scan_entry'))

    return render_template('student/scan_mode_selector.html')  

@app.route('/student/scan-qr', methods=['GET', 'POST'])
@role_required('student')
def scan_qr():
    scan_time_str = session.get('scan_verified_at')
    if not scan_time_str or datetime.utcnow() - datetime.fromisoformat(scan_time_str) > timedelta(minutes=15):
        flash("Please scan the valid QR first to proceed.", "warning")
        return redirect(url_for('scan_entry'))

    scan_time_str = session.get('scan_verified_at')
    scan_type = session.get('scan_type', 'unknown')
    if scan_time_str:
        scanned_at = datetime.fromisoformat(scan_time_str)
        time_elapsed = (datetime.utcnow() - scanned_at).total_seconds() / 60
        print(f"[DEBUG] ✅ Scan type: {scan_type}")
        print(f"[DEBUG] 🕒 Time since scan: {round(time_elapsed, 2)} minutes")
    else:
        print("[DEBUG] ❌ No scan_verified_at found in session.")

    print(f"[DEBUG] Session data: {dict(session)}")

    student_ip = request.headers.get('X-Forwarded-For') or request.remote_addr
    print(f"[QR SCAN PAGE] Student IP: {student_ip}")
    if request.method == 'POST':
        token = request.form['token']

        qr_session = QRCodeSession.query.filter_by(token=token, mode='qr').first()

        if not qr_session:
            flash("No active QR session found. Please contact your teacher.", "warning")
            return render_template('student/scan_qr.html')

        if qr_session.expires_at < datetime.now():
            flash("QR code has expired!", "warning")
            return render_template('student/scan_qr.html')

        if qr_session.institution_id != current_user.institution_id:
            flash("This QR code belongs to a different institution.", "danger")
            return render_template('student/scan_qr.html')

        institution = InstitutionDetails.query.get(current_user.institution_id)
        institution_type = institution.type.lower() if institution else 'school'

        student_ip = request.headers.get('X-Forwarded-For') or request.remote_addr
        institution = InstitutionDetails.query.get(current_user.institution_id)
        wifi_enabled_by_admin = institution.wifi_restriction_enabled if institution else False

        if qr_session.wifi_restriction and wifi_enabled_by_admin:
            teacher_ip = qr_session.teacher_ip
            if teacher_ip and student_ip != teacher_ip:
                flash('WiFi Restriction: You must be connected to the institution network to mark attendance.', 'danger')
                print(f"[WiFi Blocked] Student IP: {student_ip} ≠ Teacher IP: {teacher_ip}")
                return render_template('student/scan_qr.html')
    
        if current_user.class_name != qr_session.class_name:
            flash('Class does not match.', 'error')
            return render_template('student/scan_qr.html')

        if institution_type == 'school':

            if current_user.class_name.startswith('11') or current_user.class_name.startswith('12'):
                if current_user.stream_or_semester != qr_session.stream_or_semester:
                    flash('Stream does not match for your class!', 'error')
                    return render_template('student/scan_qr.html')

        elif institution_type in ['college', 'university']:
            if current_user.degree != qr_session.degree:
                flash('Degree does not match!', 'error')
                return render_template('student/scan_qr.html')

            
            student_subjects = [s.strip().lower() for s in (current_user.subject or '').split(',')]
            qr_subject = (qr_session.subject or '').strip().lower()

            if qr_subject not in student_subjects:
                flash('Subject does not match your enrolled subjects!', 'error')
                return render_template('student/scan_qr.html')

        today = datetime.now().date()

        if institution_type in ['college', 'university']:
            
            existing = Attendance.query.filter(
                Attendance.student_id == current_user.id,
                Attendance.teacher_id == qr_session.teacher_id,
                Attendance.subject == qr_session.subject,
                Attendance.degree == qr_session.degree,
                func.date(Attendance.date) == today
            ).first()
        else:
            
            existing = Attendance.query.filter(
                Attendance.student_id == current_user.id,
                func.date(Attendance.date) == today
            ).first()

        if existing:
            flash('Attendance already marked for today!', 'warning')
            return render_template('student/scan_qr.html')

        attendance = Attendance(
            student_id=current_user.id,
            teacher_id=qr_session.teacher_id,
            class_name=qr_session.class_name,
            subject=qr_session.subject,
            stream_or_semester=current_user.stream_or_semester or '',
            degree=current_user.degree or '',
            institution_id=current_user.institution_id,  
            date=today,
            status='Present',
            method='QR',
            roll_number=current_user.roll_number,
        )
        db.session.add(attendance)
        db.session.commit()

        flash('Attendance marked successfully via QR!', 'success')
        return redirect(url_for('student_dashboard'))
    
    return render_template('student/scan_qr.html')

@app.route('/student/scan-face')
@role_required('student')
def scan_face():
    scan_time_str = session.get('scan_verified_at')
    if not scan_time_str or datetime.utcnow() - datetime.fromisoformat(scan_time_str) > timedelta(minutes=15):
        flash("Please scan the valid QR first to proceed.", "warning")
        return redirect(url_for('scan_entry'))
    if not current_user.photo:
        flash("You must upload your face photo in your profile before using biometric attendance.", "danger")
        return redirect(url_for('edit_own_profile'))  

    latest_session = QRCodeSession.query.filter_by(
        class_name=current_user.class_name,
        institution_id=current_user.institution_id,
        mode='biometric'
    ).order_by(QRCodeSession.expires_at.desc()).first()

    if not latest_session or latest_session.expires_at < datetime.now():
        flash("No active biometric session found. Please contact your teacher.", "warning")
        return redirect(url_for('student_dashboard'))

    return render_template('student/biometric_camera.html', session=latest_session)

import cv2
import numpy as np
import base64
from io import BytesIO
from PIL import Image

import traceback

@app.route('/face-match', methods=['POST'])
@role_required('student')
def face_match():
    try:
        scan_time_str = session.get('scan_verified_at')
        if not scan_time_str or datetime.utcnow() - datetime.fromisoformat(scan_time_str) > timedelta(minutes=15):
            flash("Please scan the valid QR first to proceed.", "warning")
            return jsonify({'redirect': url_for('scan_entry')})

        student_ip = request.headers.get('X-Forwarded-For') or request.remote_addr

        image_data = request.form.get('image_data')
        if not image_data:
            flash("No image captured!", "error")
            html = render_template('student/biometric_camera.html')
            return jsonify({'html': html})

        try:
            image_bytes = base64.b64decode(image_data)
            np_arr = np.frombuffer(image_bytes, np.uint8)
            uploaded_img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            if uploaded_img is None:
                raise ValueError("cv2.imdecode returned None")
        except Exception as e:
            print("❌ Image decode error:", e)
            flash("Failed to process captured image.", "error")
            html = render_template('student/biometric_camera.html')
            return jsonify({'html': html})

        gray_uploaded = cv2.cvtColor(uploaded_img, cv2.COLOR_BGR2GRAY)
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        faces_uploaded = face_cascade.detectMultiScale(gray_uploaded, 1.1, 5)

        if len(faces_uploaded) == 0:
            flash("No face detected!", "error")
            html = render_template('student/biometric_camera.html')
            return jsonify({'html': html})

        x, y, w, h = faces_uploaded[0]
        test_face = gray_uploaded[y:y+h, x:x+w]
        test_face = cv2.resize(test_face, (200, 200))

        ref_path = os.path.join('static', current_user.photo)
        if os.path.exists(ref_path):
            ref_img = cv2.imread(ref_path)
        else:
            fallback_base64 = request.form.get('fallback_image')
            if not fallback_base64:
                flash("Reference photo not found!", "error")
                html = render_template('student/biometric_camera.html')
                return jsonify({'html': html})
            try:
                header, encoded = fallback_base64.split(",", 1)
                image_bytes = base64.b64decode(encoded)
                np_arr = np.frombuffer(image_bytes, np.uint8)
                ref_img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            except Exception:
                flash("Failed to decode fallback reference photo.", "error")
                html = render_template('student/biometric_camera.html')
                return jsonify({'html': html})

        if ref_img is None:
            flash("Failed to load reference image.", "error")
            html = render_template('student/biometric_camera.html')
            return jsonify({'html': html})

        gray_ref = cv2.cvtColor(ref_img, cv2.COLOR_BGR2GRAY)
        faces_ref = face_cascade.detectMultiScale(gray_ref, 1.1, 5)
        if len(faces_ref) == 0:
            flash("No face found in reference photo!", "error")
            html = render_template('student/biometric_camera.html')
            return jsonify({'html': html})

        x_ref, y_ref, w_ref, h_ref = faces_ref[0]
        ref_face = gray_ref[y_ref:y_ref+h_ref, x_ref:x_ref+w_ref]
        ref_face = cv2.resize(ref_face, (200, 200))

        try:
            recognizer = cv2.face.LBPHFaceRecognizer_create()
            recognizer.train([ref_face], np.array([1]))
            label, confidence = recognizer.predict(test_face)
        except Exception as e:
            flash("Error during face recognition.", "error")
            html = render_template('student/biometric_camera.html')
            return jsonify({'html': html})

        if confidence >= 60:
            flash("Face did not match!", "error")
            html = render_template('student/biometric_camera.html')
            return jsonify({'html': html})

        qr_session = QRCodeSession.query.filter_by(
            institution_id=current_user.institution_id,
            mode='biometric'
        ).order_by(QRCodeSession.expires_at.desc()).first()

        if not qr_session or qr_session.expires_at < datetime.now():
            flash("No active biometric session found. Contact teacher.", "error")
            html = render_template('student/biometric_camera.html')
            return jsonify({'html': html})

        institution = InstitutionDetails.query.get(current_user.institution_id)
        institution_type = institution.type.lower() if institution else 'school'
        wifi_enabled_by_admin = institution.wifi_restriction_enabled if institution else False

        if qr_session.wifi_restriction and wifi_enabled_by_admin:
            teacher_ip = qr_session.teacher_ip
            if teacher_ip and student_ip != teacher_ip:
                flash('WiFi Restriction: You must be connected to the institution network to mark attendance.', 'danger')
                print(f"[WiFi Blocked] Student IP: {student_ip} ≠ Teacher IP: {teacher_ip}")
                html = render_template('student/biometric_camera.html')
                return jsonify({'html': html})

        if current_user.class_name != qr_session.class_name:
            flash("Class does not match!", "error")
            html = render_template('student/biometric_camera.html')
            return jsonify({'html': html})

        if institution_type == 'school' and (current_user.class_name.startswith('11') or current_user.class_name.startswith('12')):
            if current_user.stream_or_semester != qr_session.stream_or_semester:
                flash("Stream does not match for your class!", "error")
                html = render_template('student/biometric_camera.html')
                return jsonify({'html': html})

        if institution_type in ['college', 'university']:
            if current_user.degree != qr_session.degree:
                flash("Degree does not match!", "error")
                html = render_template('student/biometric_camera.html')
                return jsonify({'html': html})

            student_subjects = [s.strip().lower() for s in (current_user.subject or '').split(',')]
            session_subject = (qr_session.subject or '').strip().lower()
            if session_subject not in student_subjects:
                flash("Subject does not match your enrolled subjects!", "error")
                html = render_template('student/biometric_camera.html')
                return jsonify({'html': html})

        today = datetime.now().date()
        if institution_type in ['college', 'university']:
            existing = Attendance.query.filter(
                Attendance.student_id == current_user.id,
                Attendance.teacher_id == qr_session.teacher_id,
                Attendance.subject == qr_session.subject,
                Attendance.degree == qr_session.degree,
                func.date(Attendance.date) == today
            ).first()
        else:
            existing = Attendance.query.filter(
                Attendance.student_id == current_user.id,
                Attendance.class_name == qr_session.class_name,
                func.date(Attendance.date) == today
            ).first()

        if existing:
            flash("Attendance already marked for today!", "warning")
            return jsonify({'redirect': url_for('student_dashboard')})

        attendance = Attendance(
            student_id=current_user.id,
            teacher_id=qr_session.teacher_id,
            class_name=qr_session.class_name,
            subject=qr_session.subject,
            stream_or_semester=current_user.stream_or_semester or '',
            degree=current_user.degree or '',
            institution_id=current_user.institution_id,
            date=today,
            status='Present',
            method='Biometric',
            roll_number=current_user.roll_number,
        )
        db.session.add(attendance)
        db.session.commit()

        flash("Attendance marked successfully via Face Recognition!", "success")
        return jsonify({'redirect': url_for('student_dashboard')})

    except Exception as e:
        print("Error in /face-match route:", str(e))
        traceback.print_exc()

        html = render_template('student/biometric_camera.html')
        return jsonify({
            'html': html,
            'error': str(e)
        }), 500

@app.route('/send-otps', methods=['POST'])
def send_otps():
    data = request.get_json()
    email = data.get('email')
    role = data.get('role')
    if current_user.is_authenticated and email.strip().lower() == current_user.email.strip().lower():
        return jsonify({
            'success': False,
            'message': 'Do not enter your own email. Please provide the parent\'s email address.'
        }), 400
        
    otp = random.randint(100000, 999999)

    
    session['otp'] = str(otp)
    session['otp_email'] = email
    session['otp_role'] = role

    
    try:
        msg = Message('Your OTP for Registration', recipients=[email])
        msg.body = f'Your OTP for registration is: {otp}'
        mail.send(msg)
        return jsonify({'success': True})
    except Exception as e:
        print("Email send error:", e)
        return jsonify({'success': False, 'message': 'Email sending failed.'}), 500

@app.route('/student/parent-contact', methods=['GET', 'POST'])
@role_required('student')
def parent_contact():
    contact = ParentContact.query.filter_by(student_id=current_user.id).first()

    if request.method == 'POST':
        
        entered_otp = request.form.get('otp')
        session_otp = session.get('otp')
        session_email = session.get('otp_email')

        if not entered_otp or entered_otp != session_otp or session_email != request.form['email']:
            flash('Invalid or missing OTP. Please try again.', 'danger')
            return redirect(url_for('parent_contact'))

        
        if contact:
            contact.parent_name = request.form['parent_name']
            contact.phone = request.form['phone']
            contact.email = request.form['email']
        else:
            contact = ParentContact(
                student_id=current_user.id,
                parent_name=request.form['parent_name'],
                phone=request.form['phone'],
                email=request.form['email']
            )
            db.session.add(contact)

        db.session.commit()

        
        session.pop('otp', None)
        session.pop('otp_email', None)
        session.pop('otp_role', None)

        flash('Parent contact updated successfully!', 'success')
        return redirect(url_for('student_dashboard'))

    return render_template('student/parent_contact.html', contact=contact)

@app.route('/parent/dashboard')
@role_required('parent')
def parent_dashboard():
    parent_email = current_user.email.lower()
    children_contacts = ParentContact.query.filter(
        func.lower(ParentContact.email) == parent_email
    ).all()

    current_month = datetime.now().strftime('%b')
    children_data = []
    institution_type = 'school'  

    for contact in children_contacts:
        student = User.query.get(contact.student_id)
        if student and student.role == 'student':
            
            institution = InstitutionDetails.query.get(student.institution_id)
            if institution and institution.type:
                institution_type = institution.type.strip().lower()

            attendance_records = Attendance.query.filter_by(student_id=student.id).order_by(Attendance.date.desc()).all()
            total_classes = len(attendance_records)
            present_count = len([a for a in attendance_records if a.status == 'Present'])
            attendance_percentage = (present_count / total_classes * 100) if total_classes > 0 else 0

            children_data.append({
                'child': student,
                'total_classes': total_classes,
                'present_count': present_count,
                'attendance_percentage': attendance_percentage,
                'recent_attendance': attendance_records
            })

    if not children_data:
        flash('No students linked to your account.', 'warning')
        return redirect(url_for('logout'))

    return render_template('parent/dashboard.html',
                           children_data=children_data,
                           current_month=current_month,
                           institution_type=institution_type)

@app.route('/teacher-list', methods=['GET', 'POST'])
@login_required
def teacher_list():
    if current_user.role not in ('admin', 'teacher'):
        flash("Unauthorized access", "danger")
        return redirect(url_for('index'))

    inst_id = current_user.institution_id
    institution = InstitutionDetails.query.get(inst_id)
    institution_type = institution.type.lower() if institution else 'school'

    
    selected_class = request.form.get('class_name')
    selected_stream = request.form.get('stream_or_semester')
    selected_subject = request.form.get('subject')
    selected_degree = request.form.get('degree')

    
    teacher_query = User.query.filter_by(role='teacher', institution_id=inst_id)
    
    if selected_class:
        assigned_teacher_ids = db.session.query(TeacherClassAssignment.teacher_id).filter_by(class_name=selected_class).distinct()
        teacher_query = teacher_query.filter(User.id.in_(assigned_teacher_ids))

    teachers = teacher_query.all()
    teacher_ids = [t.id for t in teachers]

    all_assignments = TeacherClassAssignment.query.filter(TeacherClassAssignment.teacher_id.in_(teacher_ids)).all()

    
    from collections import defaultdict
    assignments_map = defaultdict(list)
    for a in all_assignments:
        if selected_stream and a.stream_or_semester != selected_stream:
            continue
        if selected_subject and a.subject != selected_subject:
            continue
        if selected_degree and a.degree != selected_degree:
            continue
        assignments_map[a.teacher_id].append(a)

    
    enriched_teachers = []
    for t in teachers:
        assignments = assignments_map.get(t.id, [])

        class_names = sorted({a.class_name for a in assignments})
        streams = sorted({a.stream_or_semester for a in assignments if a.stream_or_semester})
        subjects = sorted({a.subject for a in assignments if a.subject})
        degrees = sorted({a.degree for a in assignments if a.degree})

        enriched_teachers.append({
            'id': t.id,  
            'username': t.username,
            'email': t.email,
            'classes': ', '.join(class_names) if class_names else '-',
            'streams': ', '.join(streams) if streams else '-',
            'subjects': ', '.join(subjects) if subjects else '-',
            'degrees': ', '.join(degrees) if degrees else '-'
        })

    
    all_assignments_all = TeacherClassAssignment.query.join(User).filter(User.institution_id == inst_id).all()
    classes = sorted({a.class_name for a in all_assignments_all if a.class_name})
    streams = sorted({a.stream_or_semester for a in all_assignments_all if a.stream_or_semester})
    subjects = sorted({a.subject for a in all_assignments_all if a.subject})
    degrees = sorted({a.degree for a in all_assignments_all if a.degree})
    current_user_role = current_user.role
    return render_template('teacher_list.html',
        teachers=enriched_teachers,
        classes=classes,
        streams=streams,
        subjects=subjects,
        degrees=degrees,
        selected_class=selected_class,
        selected_stream=selected_stream,
        selected_subject=selected_subject,
        selected_degree=selected_degree,
        institution_type=institution_type,
                           current_user_role=current_user_role
    )

@app.route('/student-list', methods=['GET', 'POST'])
@login_required
def student_list():
    if current_user.role not in ('admin', 'teacher'):
        flash("Unauthorized access", "danger")
        return redirect(url_for('index'))

    inst_id = current_user.institution_id
    institution = InstitutionDetails.query.get(inst_id)
    institution_type = institution.type.lower() if institution else 'school'

    selected_class = request.form.get('class_name')
    selected_stream = request.form.get('stream_or_semester')
    selected_subject = request.form.get('subject')
    selected_degree = request.form.get('degree')

    query = User.query.filter_by(role='student', institution_id=inst_id)

    if selected_class:
        query = query.filter(User.class_name == selected_class)

    
    if institution_type == 'school':
        if selected_class and (selected_class.startswith('11') or selected_class.startswith('12')) and selected_stream:
            query = query.filter(User.stream_or_semester == selected_stream)
    else:
        if selected_subject:
            query = query.filter(User.subject == selected_subject)
        if selected_degree:
            query = query.filter(User.degree == selected_degree)

    students = query.all()

    
    all_students = User.query.filter_by(role='student', institution_id=inst_id).all()
    classes = sorted({u.class_name for u in all_students if u.class_name})
    streams = sorted({u.stream_or_semester for u in all_students if u.stream_or_semester})
    subjects = sorted({u.subject for u in all_students if u.subject})
    degrees = sorted({u.degree for u in all_students if u.degree})

    return render_template('student_list.html',
        students=students,
        classes=classes,
        streams=streams,
        subjects=subjects,
        degrees=degrees,
        selected_class=selected_class,
        selected_stream=selected_stream,
        selected_subject=selected_subject,
        selected_degree=selected_degree,
        institution_type=institution_type
    )

SUPERADMIN_USERNAME = 'ClassiX MultiMosaic'
SUPERADMIN_PASSWORD = 'classixmultimosaic6708@'  

@app.route('/create-superadmin')
def create_superadmin_route():
    from werkzeug.security import generate_password_hash

    if not User.query.filter_by(username='superadmin').first():
        superadmin = User(
            username='ClassiX MultiMosaic',
            email='multimosaic.help@gmail.com',
            password=generate_password_hash('classixmultimosaic6708@'),
            role='superadmin',
            status='active'
        )
        db.session.add(superadmin)
        db.session.commit()
        return "Superadmin created successfully!"
    return "Superadmin already exists."

@app.route('/superadmin/dashboard')
def superadmin_dashboard():
    if current_user.role != 'superadmin':
        return redirect('/')

    users = User.query.all()
    categorized = {
        'admins': [u for u in users if u.role == 'admin'],
        'teachers': [u for u in users if u.role == 'teacher'],
        'students': [u for u in users if u.role == 'student'],
        'parents': [u for u in users if u.role == 'parent']
    }
    return render_template('superadmin_dashboard.html', users=categorized)

from sqlalchemy import or_

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if current_user.role != 'superadmin':
        return "Unauthorized", 403

    user = User.query.get(user_id)

    if user and user.role != 'superadmin':
        
        from models import Attendance, PromotionLog, QRCodeSession, ParentContact, TeacherClassAssignment

        Attendance.query.filter(
            or_(Attendance.student_id == user.id, Attendance.teacher_id == user.id)
        ).delete(synchronize_session=False)

        PromotionLog.query.filter(
            or_(PromotionLog.student_id == user.id, PromotionLog.admin_id == user.id)
        ).delete(synchronize_session=False)

        QRCodeSession.query.filter(QRCodeSession.teacher_id == user.id).delete(synchronize_session=False)

        ParentContact.query.filter(ParentContact.student_id == user.id).delete(synchronize_session=False)

        TeacherClassAssignment.query.filter(TeacherClassAssignment.teacher_id == user.id).delete(synchronize_session=False)

        
        from models import InstitutionDetails
        InstitutionDetails.query.filter(InstitutionDetails.admin_id == user.id).delete(synchronize_session=False)

        db.session.delete(user)
        db.session.commit()

    return redirect(url_for('superadmin_dashboard'))

@app.route('/super-logout')
def super_logout():
    if current_user.role != 'superadmin':
        return "Unauthorized", 403
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('super_login'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500

@app.errorhandler(Exception)
def handle_exception(e):
    return render_template('errors/general.html', error=e), 500

@app.route('/search-users')
@login_required
def search_users():
    query = request.args.get('q', '').strip()
    users = []

    if query:
        if current_user.role == 'superadmin':
            users = User.query.filter(
                User.username.ilike(f"%{query}%")
            ).all()
        elif current_user.institution_id:
            users = User.query.filter(
                User.institution_id == current_user.institution_id,
                User.username.ilike(f"%{query}%")
            ).all()

    return render_template('common/search_results.html', users=users, search_term=query)

@app.route('/chat/<int:user_id>')
@login_required
def chat_with_user(user_id):
    user_to_chat = User.query.get_or_404(user_id)

    if current_user.role != 'superadmin':
        if user_to_chat.institution_id != current_user.institution_id and user_to_chat.role != 'superadmin':
            flash("You can only chat with users in your institution.", "danger")
            return redirect(url_for('search_users'))

    return render_template("chat/chat_ui.html", user=user_to_chat)

@app.route('/chat/send', methods=['POST'])
@login_required
def send_chat():
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    content = data.get('content')

    
    if not receiver_id or not content:
        return jsonify({'error': 'Missing receiver_id or content'}), 400

    receiver = User.query.get_or_404(receiver_id)

    if current_user.role != 'superadmin':
        if receiver.institution_id != current_user.institution_id and receiver.role != 'superadmin':
            return jsonify({'error': 'Unauthorized'}), 403

    
    message = ChatMessage(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        content=content
    )
    db.session.add(message)
    db.session.commit()

    
    now = datetime.utcnow()
    log = ChatNotificationLog.query.filter_by(
        sender_id=current_user.id,
        receiver_id=receiver_id
    ).first()

    should_send_email = False

    if not log:
        should_send_email = True
        log = ChatNotificationLog(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            last_sent=now
        )
        db.session.add(log)
    elif log.last_sent < now - timedelta(hours=1):
        should_send_email = True
        log.last_sent = now

    if should_send_email and receiver.email:
        subject = f"📩 New message from {current_user.username}"
        body = f"""Hello {receiver.username},

You have received a new message from {current_user.username}.

Message:
"{content}"

Reply here: {url_for('chat_with_user', user_id=current_user.id, _external=True)}

Regards,
ClassiX
"""
        send_email_notification(to_email=receiver.email, subject=subject, body=body)

    db.session.commit()
    return jsonify({'success': True})

@app.route('/chat/messages/<int:user_id>')
@login_required
def get_messages(user_id):
    other_user = User.query.get_or_404(user_id)
    if current_user.role != 'superadmin':
        if other_user.institution_id != current_user.institution_id and other_user.role != 'superadmin':
            return jsonify({'error': 'Unauthorized'}), 403

    messages = ChatMessage.query.filter(
        ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == user_id)) |
        ((ChatMessage.sender_id == user_id) & (ChatMessage.receiver_id == current_user.id))
    ).order_by(ChatMessage.timestamp.asc()).all()

    return jsonify({
        'messages': [
            {'sender_id': m.sender_id, 'content': m.content, 'timestamp': m.timestamp.strftime('%H:%M')}
            for m in messages
        ]
    })

@app.route('/chat/delete/<int:user_id>', methods=['DELETE'])
@login_required
def delete_chat(user_id):
    other_user = User.query.get_or_404(user_id)
    if current_user.role != 'superadmin':
        if other_user.institution_id != current_user.institution_id and other_user.role != 'superadmin':
            return jsonify({'error': 'Unauthorized'}), 403

    ChatMessage.query.filter(
        ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == user_id)) |
        ((ChatMessage.sender_id == user_id) & (ChatMessage.receiver_id == current_user.id))
    ).delete()

    db.session.commit()
    return jsonify({'success': True})

@app.route('/chat/history')
@login_required
def chat_history():
    session['last_chat_visit'] = datetime.utcnow().isoformat()
    from sqlalchemy import or_, and_
    user_id = current_user.id

    
    messages = ChatMessage.query.filter(
        or_(
            ChatMessage.sender_id == user_id,
            ChatMessage.receiver_id == user_id
        )
    ).all()

    user_ids = set()
    for msg in messages:
        if msg.sender_id != user_id:
            user_ids.add(msg.sender_id)
        if msg.receiver_id != user_id:
            user_ids.add(msg.receiver_id)

    query = User.query.filter(User.id.in_(user_ids))
    if current_user.role != 'superadmin':
        query = query.filter(
            or_(
                User.institution_id == current_user.institution_id,
                User.role == 'superadmin'
            )
        )

    users = query.all()

    return render_template("chat/history.html", users=users)

@app.route('/chat/has-new')
@login_required
def chat_has_new():
    last_check = session.get('last_chat_visit')

    
    if isinstance(last_check, str):
        try:
            last_check = datetime.fromisoformat(last_check)
        except ValueError:
            last_check = None

    if not last_check:
        last_check = datetime.utcnow() - timedelta(hours=24)

    new_msg = ChatMessage.query.filter(
        ChatMessage.receiver_id == current_user.id,
        ChatMessage.timestamp > last_check
    ).first()

    return jsonify({'new_message': bool(new_msg)})

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        topic = request.form.get('topic')
        message = request.form.get('message')

        subject = f"New {topic} from {name}"
        body = f"""
Topic: {topic}
Name: {name}
Email: {email}

Message:
{message}
"""

        
        send_email_notification(
            to_email='goodgrabs.ind@gmail.com',  
            subject=subject,
            body=body
        )

        flash("✅ Your message has been sent successfully!", 'success')
        return redirect(url_for('contact'))

    return render_template('contact.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route("/faq")
def faq():
    with open("static/data/faq.json") as f:
        faqs = json.load(f)
    return render_template("faq.html", faqs=faqs)

FAQ_PATH = os.path.join('static', 'data', 'faq.json')
with open(FAQ_PATH, 'r', encoding='utf-8') as f:
    faqs = json.load(f)

questions = [faq['question'] for faq in faqs]
answers = [faq['answer'] for faq in faqs]

vectorizer = TfidfVectorizer(stop_words='english', ngram_range=(1, 2)).fit(questions)
question_vectors = vectorizer.transform(questions)

user_context = {}
chat_history_dict = {}

def clean(text):
    text = re.sub(rf"[{string.punctuation}]", "", text.lower())
    return re.sub(r"\s+", " ", text).strip()

def keyword_overlap(q1, q2):
    s1 = set(clean(q1).split())
    s2 = set(clean(q2).split())
    if not s1 or not s2:
        return 0
    return len(s1 & s2) / len(s1 | s2)

def fuzzy_ratio(q1, q2):
    return SequenceMatcher(None, q1, q2).ratio()

def score_input(user_input):
    input_vec = vectorizer.transform([user_input])
    tfidf_scores = cosine_similarity(input_vec, question_vectors).flatten()

    scores = []
    for i, question in enumerate(questions):
        overlap = keyword_overlap(user_input, question)
        fuzzy = fuzzy_ratio(clean(user_input), clean(question))
        score = 0.4 * tfidf_scores[i] + 0.25 * overlap + 0.35 * fuzzy
        scores.append((score, i))
    scores.sort(reverse=True)
    return scores

def get_best_answer(user_input, user_id='default'):
    scores = score_input(user_input)
    top_score, top_idx = scores[0]
    top_question = questions[top_idx]
    fuzzy = fuzzy_ratio(clean(user_input), clean(top_question))

    if top_score < 0.35 and fuzzy < 0.7:
        return "I'm not sure I understand. Could you rephrase that?"

    user_context[user_id] = top_idx
    return answers[top_idx]

def get_contextual_answer(user_input, user_id='default'):
    if user_id in user_context:
        prev_idx = user_context[user_id]
        ref_question = questions[prev_idx]
        combined_input = f"{ref_question} {user_input}"
        return get_best_answer(combined_input, user_id)
    return get_best_answer(user_input, user_id)

@app.route('/ai-chat', methods=['GET'])
def ai_chat():
    return render_template('chat.html')

@app.route('/chatbot', methods=['POST'])
def chatbot():
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400

    data = request.get_json()
    user_message = data.get('message', '').strip()
    user_id = 'default'

    if user_id not in user_context:
        user_context[user_id] = None
    if user_id not in chat_history_dict:
        chat_history_dict[user_id] = []

    normalized = user_message.lower()

    greetings = {
        'hi', 'hello', 'hey', 'good morning', 'good afternoon', 'good evening', 'what’s up', 'is anyone there'
    }
    farewells = {
        'bye', 'goodbye', 'see you', 'see ya', 'take care', 'i’m done', 'that’s all for now', 'talk to you later'
    }
    gratitude = {
        'thanks', 'thank you', 'thank you very much', 'thanks a lot', 'appreciate it', 'i’m grateful', 'that helped a lot'
    }
    apologies = {
        'sorry', 'my bad', 'i didn’t mean to', 'can i try again', 'i entered wrong input'
    }
    confirmations = {
        'okay', 'ok', 'got it', 'sounds good', 'cool', 'alright', 'done', 'i understand'
    }
    small_talk = {
        'are you a bot', 'what can you do', 'who made you', 'are you intelligent',
        'can you speak hindi', 'tell me more about classix', 'are you available 24/7'
    }
    help_requests = {
        'i need help', 'help', 'can you help me', 'what should i do', 'i don’t understand',
        'what is this', 'how does this work', 'explain this', 'i’m confused', 'please guide me'
    }
    feedback_positive = {
        'this is great', 'i like it', 'awesome', 'very helpful', 'nice work', 'amazing'
    }
    feedback_negative = {
        'this is useless', 'not working', 'you’re wrong', 'bad answer', 'i hate this'
    }
    clarification = {
        'say again', 'repeat', 'can you repeat that', 'what do you mean', 'explain again', 'repeat please'
    }
    casual_fun = {
        'tell me a joke', 'how old are you', 'what’s your name', 'do you have a brain', 'are you single', 'do you dream'
    }

    if not user_message:
        bot_response = "I'm sorry, I didn't catch that. Could you try again?"
    elif normalized in greetings:
        bot_response = "Hi there! How can I help you today?"
    elif normalized in farewells:
        bot_response = "Goodbye! Feel free to come back if you have more questions."
    elif normalized in gratitude:
        bot_response = "You're welcome! Let me know if there's anything else I can help with."
    elif normalized in apologies:
        bot_response = "No worries at all. Let me know what you'd like to do next."
    elif normalized in confirmations:
        bot_response = "Great! Let me know if you need anything else."
    elif normalized in small_talk:
        bot_response = "I'm your AI assistant for ClassiX. Ask me anything about how the platform works."
    elif normalized in help_requests:
        bot_response = "Sure! I’m here to help. You can ask about dashboards, QR scanning, reports, or anything else related to ClassiX."
    elif normalized in feedback_positive:
        bot_response = "Thanks! I'm glad it's helpful 😊"
    elif normalized in feedback_negative:
        bot_response = "I'm sorry to hear that. Let me try to give a better answer."
    elif normalized in clarification:
        last_bot = next((item['text'] for item in reversed(chat_history_dict[user_id]) if item['sender'] == 'bot'), "I'm here to help.")
        bot_response = f"Sure! Let me repeat: {last_bot}"
    elif normalized in casual_fun:
        bot_response = "I'm just lines of code, but I dream of clean JSON and fast queries 😄"
    elif len(normalized.split()) <= 4 and re.search(r'\b(this|that|how|it|do it|what about)\b', normalized):
        bot_response = get_contextual_answer(user_message, user_id)
    else:
        bot_response = get_best_answer(user_message, user_id)
        user_context[user_id] = None

    chat_history_dict[user_id].append({'sender': 'user', 'text': user_message})
    chat_history_dict[user_id].append({'sender': 'bot', 'text': bot_response})

    return jsonify({'response': bot_response})

from sqlalchemy.exc import IntegrityError

@app.route('/api/check-username', methods=['POST'])
def check_username():
    username = request.json.get('username', '').strip()
    exists = User.query.filter_by(username=username).first() is not None
    return jsonify({'exists': exists})

@app.route('/api/check-email', methods=['POST'])
def check_email():
    email = request.json.get('email', '').strip().lower()
    exists = User.query.filter_by(email=email).first() is not None
    return jsonify({'exists': exists})

@app.route('/teacher/add-students', methods=['GET', 'POST'])
@role_required('teacher')
def add_students():
    institution = InstitutionDetails.query.get(current_user.institution_id)
    if institution.type.lower() != 'school':
        flash('This feature is only for schools.', 'danger')
        return redirect(url_for('teacher_dashboard'))

    classes = [c.strip() for c in (institution.classes or '').split(',')]
    streams = [s.strip() for s in (institution.streams or '').split(',')]

    if request.method == 'POST':
        entries = request.form.getlist('students')
        errors = []
        usernames = set()
        emails = set()
        roll_numbers = set()

        for raw in entries:
            data = json.loads(raw)
            u = data['username'].strip()
            e = data['email'].strip().lower()
            r = data['roll_number'].strip()
            c = data['class_name']
            s = data.get('stream_or_semester', '').strip()

            if u in usernames:
                errors.append(f"{u}: Duplicate username in form.")
                continue
            if e in emails:
                errors.append(f"{e}: Duplicate email in form.")
                continue
            if r in roll_numbers:
                errors.append(f"{r}: Duplicate roll number in form.")
                continue

            usernames.add(u)
            emails.add(e)
            roll_numbers.add(r)

            if (c.startswith('11') or c.startswith('12')) and s not in streams:
                errors.append(f"{u}: Invalid or missing stream.")
                continue
            elif not (c.startswith('11') or c.startswith('12')):
                s = ''

            if User.query.filter((User.username == u) | (User.email == e)).first():
                errors.append(f"{u} / {e} / {r}: Already exists in system.")
                continue

            pw = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
            student = User(
                username=u,
                email=e,
                roll_number=r,
                role='student',
                status='active',
                class_name=c,
                stream_or_semester=s,
                institution_id=current_user.institution_id
            )
            student.set_password(pw)
            db.session.add(student)
            try:
                db.session.flush()
            except IntegrityError:
                db.session.rollback()
                errors.append(f"{u} / {e}: Already exists.")
            except Exception as ex:
                db.session.rollback()
                errors.append(f"{u}: Failed to create account ({ex})")

        if errors:
            flash("Some errors occurred:\n" + "\n".join(errors), 'warning')
        else:
            db.session.commit()
            flash("All students added successfully!", 'success')
            return redirect(url_for('teacher_dashboard'))

    return render_template('teacher/add_students.html', classes=classes, streams=streams)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    
    app.run(host='0.0.0.0', port=5000, debug=True)
