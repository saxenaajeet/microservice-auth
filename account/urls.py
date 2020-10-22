from django.urls import path
from .views import RegisterAccountView, SampleView, LoginApiView, LogoutApiView, GenerateOTPView
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)

app_name = "account"

urlpatterns = [
    path('register/', RegisterAccountView.as_view(), name='register'),
    path('login/', LoginApiView.as_view(), name='login'),
    path('logout/', LogoutApiView.as_view(), name='logout'),
    path('otp/', GenerateOTPView.as_view(), name='otp'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('sample/', SampleView.as_view(), name='sample')
]

urlpatterns += [
    path('token/claim/', TokenVerifyView.as_view(), name='token_verify'),

]
