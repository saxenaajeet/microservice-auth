from django.contrib.auth.models import User
import jwt
import pyotp
from django.conf import settings
from rest_framework import authentication
from rest_framework import exceptions
from .models import Account, PhoneOtp
from .utils import OtpUtils


class AccountAuthentication(authentication.BaseAuthentication):

    def authenticate(self, request):
        data = request.data
        print("data = " + str(data))
        phone = data['phone']
        password = data['password']
        if not phone:
            return None
        account = Account.objects.get(phone=phone)

        if not account:
            return None

        phoneotp = PhoneOtp.objects.get(phone=phone)
        otp_secret_key = phoneotp.otp_secret_key

        otp_utils = OtpUtils(phone, otp_secret_key)
        if otp_utils.verify(password):
            return (account, None)
        else:
            raise exceptions.AuthenticationFailed(
                "The otp password is expired or invalid")
