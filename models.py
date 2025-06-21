from flask_login import UserMixin
from datetime import datetime
from extensions import db 
from sqlalchemy.orm import aliased
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)  
    status = db.Column(db.String(20), default='pending')  
    class_name = db.Column(db.String(50))  
    stream_or_semester = db.Column(db.String(50))  
    subject = db.Column(db.String(100))  
    degree = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    institution_id = db.Column(db.Integer, db.ForeignKey('institution_details.id'))
    institution = db.relationship(
        'InstitutionDetails', 
        foreign_keys=[institution_id],
        backref=db.backref('users', lazy=True)  
    )
    last_parent_report_sent = db.Column(db.DateTime)
    roll_number = db.Column(db.String(50))

    def check_password(self, password):
        return check_password_hash(self.password, password)  

    def set_password(self, password):
        self.password = generate_password_hash(password)  

class InstitutionDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    admin = db.relationship(
        'User', 
        foreign_keys=[admin_id], 
        backref=db.backref('admin_institution', uselist=False)  
    )
    name = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(50), nullable=False)  
    country = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    medium = db.Column(db.String(50), nullable=False)  
    classes = db.Column(db.Text)  
    streams = db.Column(db.Text)  
    degrees = db.Column(db.Text)  
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    allowed_domain = db.Column(db.String(100), nullable=True)

class Pin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    institution_id = db.Column(db.Integer, db.ForeignKey('institution_details.id'), nullable=False)
    pin_code = db.Column(db.String(6), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)  
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime)

class TeacherClassAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    class_name = db.Column(db.String(50), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    stream_or_semester = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    degree = db.Column(db.String(50))
    teacher = db.relationship('User', backref='class_assignments')

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    class_name = db.Column(db.String(50), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False)
    stream_or_semester = db.Column(db.String(100))
    degree = db.Column(db.String(100))
    status = db.Column(db.String(20), nullable=False)  
    method = db.Column(db.String(20), default='manual')  
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    institution_id = db.Column(db.Integer, db.ForeignKey('institution_details.id'), nullable=False)
    student = db.relationship('User', foreign_keys=[student_id], backref='attendance_records')
    teacher = db.relationship('User', foreign_keys=[teacher_id], backref='marked_attendance')
    roll_number = db.Column(db.String(50))
    @classmethod
    def detailed_report(cls, institution_id=None, teacher_id=None,
                        class_name=None, subject=None, date=None, student_id=None, degree=None, stream_or_semester=None, roll_number=None):

        StudentAlias = aliased(User)
        TeacherAlias = aliased(User)

        query = db.session.query(cls).\
            join(StudentAlias, cls.student_id == StudentAlias.id).\
            join(TeacherAlias, cls.teacher_id == TeacherAlias.id)

        if institution_id:
            query = query.filter(StudentAlias.institution_id == institution_id)
        if teacher_id:
            query = query.filter(cls.teacher_id == teacher_id)
        if student_id:
            query = query.filter(cls.student_id == student_id)
        if class_name:
            query = query.filter(cls.class_name == class_name)
        if subject:
            query = query.filter(cls.subject == subject)
        if date:
            query = query.filter(cls.date == date)
        if roll_number:
            query = query.filter(cls.roll_number == roll_number)
        if degree:
            query = query.filter(StudentAlias.degree == degree)
        if stream_or_semester:
            query = query.filter(StudentAlias.stream_or_semester == stream_or_semester)

        return query.with_entities(
            cls.date,
            cls.class_name,
            cls.subject,
            StudentAlias.username.label('student_name'),
            cls.stream_or_semester,
            cls.degree,
            cls.status,
            cls.roll_number,
            TeacherAlias.username.label('teacher_name')
        ).order_by(cls.date.desc()).all()

class ParentContact(db.Model):
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parent_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    student = db.relationship('User', backref='parent_contact')

class PromotionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    old_class = db.Column(db.String(50), nullable=False)
    new_class = db.Column(db.String(50), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    student = db.relationship('User', foreign_keys=[student_id], backref='promotion_history')
    admin = db.relationship('User', foreign_keys=[admin_id], backref='conducted_promotions')

class QRCodeSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(50), unique=True, nullable=False)
    class_name = db.Column(db.String(50), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    stream_or_semester = db.Column(db.String(100), nullable=True)  
    degree = db.Column(db.String(100), nullable=True)
    teacher = db.relationship('User', backref='qr_sessions')
    institution_id = db.Column(db.Integer, db.ForeignKey('institution_details.id'), nullable=False)

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

class ChatNotificationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    last_sent = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    db.UniqueConstraint('sender_id', 'receiver_id')
