from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token
from django.core.validators import RegexValidator
from rest_framework_simplejwt.tokens import RefreshToken


# Create your models here.


class MyAccountManager(BaseUserManager):
    def create_user(self, phone, username, email, password=None):
        if not phone:
            raise ValueError('Users must have a phone number')
        if not username:
            raise ValueError('Users must have a username')

        user = self.model(
            phone=phone,
            username=username,
            email=self.normalize_email(email)
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone, username, email, password):
        user = self.create_user(
            phone=phone,
            password=password,
            username=username,
            email=email
        )
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class Account(AbstractBaseUser, PermissionsMixin):
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{10,14}$', message="Invalid phone number, must be entered in the format: '+9999999999'. Upto 14 digists allowed. ")
    phone = models.CharField(verbose_name="phone", validators=[
                             phone_regex], max_length=15, unique=True)
    username = models.CharField(
        max_length=20, unique=True)
    email = models.EmailField(verbose_name="email", max_length=60)
    date_joined = models.DateTimeField(
        verbose_name='date joined', auto_now_add=True)
    last_login = models.DateTimeField(verbose_name='last login', auto_now=True)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = ['username', 'email']

    objects = MyAccountManager()

    def __str__(self):
        return self.email

    # For checking permissions. to keep it simple all admin have ALL permissons
    def has_perm(self, perm, obj=None):
        return self.is_admin

    # Does this user have permission to view this app? (ALWAYS YES FOR SIMPLICITY)
    def has_module_perms(self, app_label):
        return True

    def tokens(self):
        refresh_token = RefreshToken.for_user(self)
        return {"refresh_token": str(refresh_token),
                "access_token": str(refresh_token.access_token)}


class PhoneOtp(models.Model):
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{10,14}$', message="Invalid Phone Number, must be entered in the format: '+9999999999'. Upto 14 digists allowed. ")
    phone = models.CharField(verbose_name="phone", validators=[
                             phone_regex], max_length=15, unique=True)
    otp = models.CharField(max_length=9, blank=True, null=True)
    count = models.IntegerField(default=0, help_text="Number of otp sent")
    is_validated = models.BooleanField(
        default=False, help_text="If it is true that means user have validated correctly")
    otp_secret_key = models.CharField(max_length=120, null=True, default=None)

    def __str__(self):
        return str(self.phone) + " is sent " + str(self.otp)
