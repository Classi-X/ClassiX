import time
from flask import current_app
from pyfingerprint.pyfingerprint import PyFingerprint

class FingerprintError(Exception):
    pass

def _get_sensor():
    port = current_app.config['FINGERPRINT_SERIAL_PORT']
    baud = current_app.config['FINGERPRINT_BAUDRATE']
    pwd  = current_app.config['FINGERPRINT_SENSOR_PASSWORD']

    try:
        f = PyFingerprint(port, baud, pwd)
        if not f.verifyPassword():
            raise FingerprintError('Sensor password verification failed.')
        return f
    except Exception as e:
        raise FingerprintError(f'Cannot initialize sensor on {port}: {e}')

def enroll_and_download_template():
    f = _get_sensor()

    try:
        start = time.time()
        while not f.readImage():
            if time.time() - start > 30:
                raise FingerprintError('Timeout: No finger detected (first scan).')
            time.sleep(0.1)

        f.convertImage(0x01)

        start = time.time()
        while f.readImage(): 
            if time.time() - start > 10:
                break
            time.sleep(0.1)

        start = time.time()
        while not f.readImage():
            if time.time() - start > 30:
                raise FingerprintError('Timeout: No finger detected (second scan).')
            time.sleep(0.1)

        f.convertImage(0x02)

        if not f.createTemplate():
            raise FingerprintError('Template creation failed (low quality or mismatch).')

        position_number = f.storeTemplate()

        f.loadTemplate(position_number, 0x01)
        characteristics = f.downloadCharacteristics(0x01)
        template_bytes = bytes(characteristics)

        return position_number, template_bytes

    except Exception as e:
        raise FingerprintError(str(e))

def match_fingerprint(stored_template):
    f = _get_sensor()
    try:
        start = time.time()
        while not f.readImage():
            if time.time() - start > 10:
                return False 
            time.sleep(0.1)

        f.convertImage(0x01)

        live_template = bytes(f.downloadCharacteristics(0x01))

        return live_template == stored_template

    except Exception as e:
        raise FingerprintError(f"Fingerprint scan failed: {e}")
