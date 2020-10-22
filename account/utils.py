import datetime
import base64
import pyotp
import time
from django.conf import settings
import logging

logger = logging.getLogger('account')


class OtpUtils:

    def __init__(self, phone=None, otp_secret_key=None):
        self.phone = phone
        self.otp_secret_key = otp_secret_key

    def generate_key(self):
        secret_key = str(self.phone) + str(self.otp_secret_key)
        secret_key_bytes = secret_key.encode('ascii')
        key = base64.b32encode(secret_key_bytes)
        return key

    def generateOTP(self):
        key = self.generate_key()
        totp = pyotp.TOTP(key, interval=120, digits=4)
        otp_to_send = totp.now()
        logger.info("OTP generated is %s", otp_to_send)
        return otp_to_send

    def verifyOTP(self, password):
        key = self.generate_key()
        totp = pyotp.TOTP(key, interval=120, digits=4)
        return totp.verify(password)
