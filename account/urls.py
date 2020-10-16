from django.urls import path
from .views import RegisterAccountView, GetAuthTokenView
from rest_framework.authtoken.views import obtain_auth_token

app_name = "account"

urlpatterns = [
    path('register/', RegisterAccountView.as_view(), name='register'),
    path('login/', obtain_auth_token, name='login'),
    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
