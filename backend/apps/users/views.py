"""
Views for the users app.

RegisterView        — creates a new (inactive) user and sends OTP (public).
VerifyOTPView       — verifies OTP and activates the user (public).
ResendOTPView       — re-sends a fresh OTP to the user's email (public).
MeView              — returns the authenticated user's profile (JWT required).
GoogleOAuthView     — verifies a Google ID token and issues a JWT pair (public).
LogoutView          — blacklists the refresh token to invalidate the session (JWT required).
ForgotPasswordView  — sends a password-reset OTP to the user's email (public).
ResetPasswordView   — validates OTP + new password to reset credentials (public).
"""

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from .serializers import (
    ForgotPasswordSerializer,
    GoogleOAuthSerializer,
    RegisterSerializer,
    ResendOTPSerializer,
    ResetPasswordSerializer,
    UserSerializer,
    VerifyOTPSerializer,
)

User = get_user_model()


class RegisterView(APIView):
    """
    Public endpoint for new user registration.

    POST /api/auth/register/
    Accepts: { username, email, password, first_name, last_name, invite_code }
    Returns: { message, email } on success (201).

    The user is created as inactive.  An OTP is sent to the provided
    email address.  The user must verify the OTP before they can log in.
    """

    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        """
        Validate registration payload, create an inactive user,
        and send an OTP to their email.

        Args:
            request: DRF request containing registration fields.

        Returns:
            201 Created with { message, email }, or 400 with errors.
        """
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(
                {
                    "message": "Verification code sent to your email.",
                    "email": user.email,
                },
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    """
    Public endpoint for OTP verification.

    POST /api/auth/register/verify-otp/
    Accepts: { email, otp }
    Returns: { message } on success (200).
    """

    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        """
        Verify the OTP and activate the user account.

        Args:
            request: DRF request containing email and otp.

        Returns:
            200 OK on success, 400 with validation errors otherwise.
        """
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            return Response(
                {"message": "Email verified successfully. You can now sign in."},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResendOTPView(APIView):
    """
    Public endpoint for re-sending an OTP.

    POST /api/auth/register/resend-otp/
    Accepts: { email }
    Returns: { message } on success (200).
    """

    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        """
        Generate and send a fresh OTP to the given email.

        Args:
            request: DRF request containing the email address.

        Returns:
            200 OK on success, 400 with validation errors otherwise.
        """
        serializer = ResendOTPSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "A new verification code has been sent."},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class MeView(APIView):
    """
    Returns the profile of the currently authenticated user.

    GET /api/auth/me/
    Requires: Bearer JWT token in Authorization header.
    Returns: { id, username, email, first_name, last_name, date_joined,
               is_verified, is_demo, aws_role_arn, auth_method }
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """
        Serialize and return the authenticated user's profile.

        Args:
            request: DRF request with a valid JWT in the Authorization header.

        Returns:
            200 OK with the user's serialized profile.
        """
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


class GoogleOAuthView(APIView):
    """
    Authenticates a user via a Google ID token and returns a JWT pair.

    POST /api/auth/google/
    Accepts: { id_token: <Google ID token string> }
    Returns: { access, refresh, user } on success (200).

    The ID token is obtained by the frontend from Google Identity Services
    after the user completes the Google sign-in consent screen.  This view
    delegates all token verification and user resolution to
    GoogleOAuthSerializer.  No invite code is required.

    The JWT pair is issued by constructing a RefreshToken directly from the
    resolved user, which runs MayaTrailTokenObtainPairSerializer.get_token()
    and embeds all custom claims (is_verified, is_demo, auth_method, etc.).
    """

    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        """
        Verify the Google ID token and issue a MayaTrail JWT pair.

        Args:
            request: DRF request containing { id_token }.

        Returns:
            200 OK with { access, refresh, user } on success.
            400 Bad Request with validation errors on failure.
        """
        serializer = GoogleOAuthSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data["user"]

        # RefreshToken.for_user() calls get_token() on the configured
        # TOKEN_OBTAIN_SERIALIZER, which injects our custom claims.
        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": UserSerializer(user).data,
            },
            status=status.HTTP_200_OK,
        )


class LogoutView(APIView):
    """
    Blacklists the user's refresh token to invalidate their session.

    POST /api/auth/logout/
    Accepts: { refresh: <refresh token string> }
    Returns: 205 Reset Content on success.

    The refresh token is added to the blacklist so it can no longer be
    used to obtain new access tokens.  The client should also discard
    both tokens from local storage after calling this endpoint.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        """
        Blacklist the provided refresh token.

        Args:
            request: DRF request containing { refresh }.

        Returns:
            205 Reset Content on success.
            400 Bad Request if the token is missing or already blacklisted.
        """
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response(
                {"detail": "Refresh token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            return Response(
                {"detail": "Token is invalid or already blacklisted."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(status=status.HTTP_205_RESET_CONTENT)


class ForgotPasswordView(APIView):
    """
    Sends a password-reset OTP to the given email address.

    POST /api/auth/forgot-password/
    Accepts: { email }
    Returns: 200 { message } — always succeeds to prevent email enumeration.
    """

    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"message": "If an account exists, a reset code has been sent."},
            status=status.HTTP_200_OK,
        )


class ResetPasswordView(APIView):
    """
    Validates a reset OTP and sets a new password.

    POST /api/auth/reset-password/
    Accepts: { email, otp, new_password }
    Returns: 200 { message } on success, 400 with errors on failure.
    """

    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"message": "Password has been reset successfully."},
            status=status.HTTP_200_OK,
        )
