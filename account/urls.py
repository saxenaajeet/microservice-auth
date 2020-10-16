from django.urls import path
from .views import RegisterAccountView

app_name = "account"

urlpatterns = [
    path('register/', RegisterAccountView.as_view(), name='register'),
    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]
