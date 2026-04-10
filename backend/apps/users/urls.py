"""
URL routing for the users app.

Mounted at /api/auth/ in config/urls.py.
"""

from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import GoogleOAuthView, LogoutView, MeView, RegisterView, ResendOTPView, VerifyOTPView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="auth-register"),
    path("register/verify-otp/", VerifyOTPView.as_view(), name="auth-verify-otp"),
    path("register/resend-otp/", ResendOTPView.as_view(), name="auth-resend-otp"),
    path("login/", TokenObtainPairView.as_view(), name="auth-login"),
    path("refresh/", TokenRefreshView.as_view(), name="auth-refresh"),
    path("logout/", LogoutView.as_view(), name="auth-logout"),
    path("me/", MeView.as_view(), name="auth-me"),
    path("google/", GoogleOAuthView.as_view(), name="auth-google"),
]
