import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'classix_multimosaic_6708@'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///classix.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  

    
    PERMANENT_SESSION_LIFETIME = timedelta(days=365)

    
    MAIL_SERVER = "smtp.gmail.com"
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = "multimosaic.help@gmail.com"
    MAIL_PASSWORD = "sahx xwrl rorx irbh"
    MAIL_DEFAULT_SENDER = 'multimosaic.help@gmail.com'

    TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID') or 'ACe22c004acbbbef75cec10cd919dbea35'
    TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN') or '1aaaefedc9f99d3858da6b97d77f1411'
    TWILIO_WHATSAPP_FROM = 'whatsapp:+14155238886'  

    
    QR_CODE_EXPIRY_MINUTES = 15

    
    MINIMUM_ATTENDANCE_PERCENTAGE = 75

    FINGERPRINT_SERIAL_PORT = os.getenv('FINGERPRINT_SERIAL_PORT', '/dev/ttyUSB0')  # e.g. 'COM3' on Windows
    FINGERPRINT_BAUDRATE = int(os.getenv('FINGERPRINT_BAUDRATE', '57600'))
    FINGERPRINT_SENSOR_PASSWORD = int(os.getenv('FINGERPRINT_SENSOR_PASSWORD', '0'))  # default 0x00000000
    FINGERPRINT_ENABLE = True
    FINGERPRINT_MOCK = True

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
