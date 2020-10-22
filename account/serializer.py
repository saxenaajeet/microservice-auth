from rest_framework import serializers
from account.models import Account, PhoneOtp
import re
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed, NotFound
from django.core.exceptions import ObjectDoesNotExist
from .utils import OtpUtils
import pyotp
import base64
import logging

logger = logging.getLogger('account')


class RegisterSerializer(serializers.ModelSerializer):

    class Meta:
        model = Account
        fields = ["phone", "username", "password", "email"]
        extra_kwargs = {
            'password': {'write_only': True}

        }

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')
        phone = attrs.get('phone', '')
        password = attrs.get('password', '')

        try:
            account = Account.objects.get(phone=phone)
        except account.DoesNotExist:
            raise serializers.ValidationError(
                {"phone": "This phone number is already in use."})

        PHONE_REGEX = re.compile('^\+?1?\d{10,14}$')
        if not PHONE_REGEX.match(phone):
            raise serializers.ValidationError(
                {"phone": "Invalid Phone number, must be entered in the format: '+9999999999'. Upto 14 digits allowed."})

        phoneOtp_obj = PhoneOtp.objects.get(phone=phone)
        otp_secret_key = phoneOtp_obj.otp_secret_key
        logger.info("Secret key for phone # %s is %s", phone, otp_secret_key)
        otp_utils = OtpUtils(phone, otp_secret_key)
        if password is None:
            raise serializers.ValidationError(
                {"password": "The register request does not have otp password"})
        logger.info("Input Password is %s", password)
        if not otp_utils.verifyOTP(password):
            raise AuthenticationFailed(
                "The otp password is expired or invalid")

        EMAIL_REGEX = re.compile(r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$')
        if not EMAIL_REGEX.match(email):
            raise serializers.ValidationError(
                {"email": "Email should be in correct format"})

        if not username.isalnum():
            raise serializers.ValidationError(
                "The username should not contain alpha numeric character")
        return attrs

    def save(self):
        account = Account(
            phone=self.validated_data['phone'],
            username=self.validated_data['username']
        )
        password = self.validated_data['password']
        account.set_password(password)
        account.save()
        return account


class LoginSerializer(serializers.ModelSerializer):

    phone = serializers.CharField(max_length=15, min_length=10)
    password = serializers.CharField(
        max_length=10, min_length=4, write_only=True)
    username = serializers.CharField(max_length=20, read_only=True)
    tokens = serializers.EmailField(max_length=100, read_only=True)

    class Meta:
        model = Account
        fields = ["phone", "password", "username", "tokens"]

    def validate(self, attrs):
        phone = attrs.get('phone', '')
        password = attrs.get('password', '')

        if not phone:
            raise AuthenticationFailed(
                'Invalid credentials, Please enter a valid phone number !')

        if not password:
            raise AuthenticationFailed(
                'Invalid credentials, Please enter a valid OTP !')

        try:
            account = Account.objects.get(phone=phone)
        except:
            raise AuthenticationFailed(
                'Invalid credentials, User account does not exist !')

        if not account.is_active:
            raise AuthenticationFailed('Account disabled, contact admin!')

        phone_otp_obj = PhoneOtp.objects.get(phone=phone)

        if phone_otp_obj:
            otp_secret_key = phone_otp_obj.otp_secret_key
            otp_utils = OtpUtils(phone, otp_secret_key)
            if not otp_utils.verifyOTP(password):
                raise AuthenticationFailed(
                    "The otp password is expired or invalid")
        else:
            raise AuthenticationFailed(
                'Invalid credentials, User has not generated the otp !')

        return {
            "phone": account.phone,
            "username": account.username,
            "tokens": account.tokens()
        }


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_message = {
        'bad_token': {'Token is expired or invalid'}
    }

    class Meta:
        pass

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')


class GenerateOTPSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=15)
    otp = serializers.CharField(max_length=9, read_only=True)

    def validate(self, attrs):
        phone = attrs.get('phone', '')
        PHONE_REGEX = re.compile('^\+?1?\d{10,14}$')
        if not PHONE_REGEX.match(phone):
            raise serializers.ValidationError(
                {"phone": "Invalid Phone number, must be entered in the format: '+9999999999'. Upto 14 digits allowed."})
        phone_obj = None
        try:
            phone_obj = PhoneOtp.objects.get(phone=phone)
        except ObjectDoesNotExist:
            PhoneOtp.objects.create(
                phone=phone, otp_secret_key=pyotp.random_hex())
            phone_obj = PhoneOtp.objects.get(phone=phone)
        phone_obj.count = phone_obj.count + 1
        phone_obj.save()
        otp_secret_key = phone_obj.otp_secret_key
        otp_utils = OtpUtils(phone=phone, otp_secret_key=otp_secret_key)
        return {"phone": phone, "password": otp_utils.generateOTP()}

    def create(self, validated_data):
        phone_obj = PhoneOtp.objects.get(phone=self.validated_data['phone'])
        phone_obj.otp = self.validated_data['password']
        phone_obj.save()
        return phone_obj
