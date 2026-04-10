"""
Serializers for the users app.

MayaTrailTokenObtainPairSerializer — custom JWT serializer that embeds
    user profile claims so the frontend can reconstruct auth state on
    page reload without an extra API round-trip.

UserSerializer     — read-only representation of the authenticated user.
RegisterSerializer — validates and creates a new (inactive) user account.
VerifyOTPSerializer — validates the OTP and activates the user.
ResendOTPSerializer — validates an email for OTP re-send.
"""

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import EmailOTP

User = get_user_model()


class MayaTrailTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Extends SimpleJWT's default serializer to embed MayaTrail-specific
    user profile claims directly into the JWT payload.

    The frontend reads these claims from localStorage on page reload
    (via getStoredUser) to reconstruct the auth state without needing
    a separate /auth/me/ call. Without these claims, is_verified and
    is_demo always default to False, causing verified users to be
    bounced to /connector on every refresh.

    Claims added:
        username       — the user's login name
        is_verified    — True when the IAM role has been verified via STS
        is_demo        — True when the user is in demo mode
        demo_used      — True if the user has ever activated demo mode
        demo_expires_at — ISO-formatted expiry timestamp, or None
    """

    @classmethod
    def get_token(cls, user: User) -> dict:
        """
        Build the base token and inject MayaTrail profile claims.

        Args:
            user: The authenticated User instance.

        Returns:
            A SimpleJWT token with additional claims attached.
        """
        token = super().get_token(user)

        token["username"] = user.username
        token["is_verified"] = user.is_verified
        token["is_demo"] = user.is_demo
        token["demo_used"] = user.demo_used
        token["demo_expires_at"] = (
            user.demo_expires_at.isoformat() if user.demo_expires_at else None
        )
        token["auth_method"] = user.auth_method

        return token


class UserSerializer(serializers.ModelSerializer):
    """
    Read-only serializer for the User model.

    Exposes a safe subset of fields.  Password is never included.
    Includes a computed ``demo_expires_at`` ISO timestamp so the
    frontend can display a countdown timer for demo users.
    """

    demo_expires_at = serializers.SerializerMethodField()
    auth_method = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id", "username", "email", "first_name", "last_name",
            "date_joined", "is_verified", "is_demo", "aws_role_arn",
            "demo_activated_at", "demo_used", "demo_expires_at", "auth_method",
        ]
        read_only_fields = fields

    def get_demo_expires_at(self, obj) -> str | None:
        """Return the ISO-formatted expiry time, or None."""
        expires = obj.demo_expires_at
        return expires.isoformat() if expires else None

    def get_auth_method(self, obj) -> str:
        """Return the authentication method: 'google_sso' or 'credentials'."""
        return obj.auth_method


class RegisterSerializer(serializers.ModelSerializer):
    """
    Write serializer used during new account registration.

    Accepts username, email, password, and an invite_code.
    Password is write-only and is hashed before storage via create().
    Email is normalised to lowercase and checked for uniqueness.

    The invite_code field is required when the REGISTRATION_INVITE_CODE
    setting is non-empty.  It is validated but never stored.

    Creates the user with is_active=False.  The user becomes active
    only after verifying the email OTP.
    """

    password = serializers.CharField(write_only=True, min_length=8)
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=False, allow_blank=True, default="")
    last_name = serializers.CharField(required=False, allow_blank=True, default="")
    invite_code = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ["username", "email", "password", "first_name", "last_name", "invite_code"]

    def validate_invite_code(self, value: str) -> str:
        """
        Check the submitted invite code against the server-side secret.

        If REGISTRATION_INVITE_CODE is empty (gate disabled), any value
        is accepted.  Otherwise, the codes must match exactly.

        Args:
            value: The invite code string from the request body.

        Returns:
            The invite code unchanged (it is not persisted).

        Raises:
            serializers.ValidationError: If the code does not match.
        """
        expected = getattr(settings, "REGISTRATION_INVITE_CODE", "")
        if expected and value != expected:
            raise serializers.ValidationError("Invalid invite code.")
        return value

    def validate_email(self, value: str) -> str:
        """
        Normalise the email to lowercase and reject duplicates.

        Checks both active and inactive users.  If an inactive user
        already exists with this email (abandoned OTP flow), they
        will be cleaned up server-side.

        Args:
            value: The raw email string from the request body.

        Returns:
            The lowercased email if it is unique.

        Raises:
            serializers.ValidationError: If the email is already taken
            by an active user.
        """
        normalised = value.lower().strip()
        # Allow re-registration if the previous attempt was never activated
        if User.objects.filter(email=normalised, is_active=True).exists():
            raise serializers.ValidationError(
                "A user with this email already exists."
            )
        return normalised

    def create(self, validated_data: dict) -> User:
        """
        Create a new inactive user and send an OTP to their email.

        The invite_code is popped from validated_data since it is a
        gate-check field and is not stored on the User model.

        If an inactive user with the same email already exists (from a
        previous abandoned registration), they are deleted first.

        Args:
            validated_data: Validated field values from the request body.

        Returns:
            The newly created (inactive) User instance.
        """
        validated_data.pop("invite_code", None)

        # Clean up any previous inactive registration for this email
        User.objects.filter(
            email=validated_data["email"], is_active=False
        ).delete()

        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
            is_active=False,  # Inactive until OTP is verified
        )

        # Generate and send OTP
        otp = EmailOTP.generate_for_email(user.email)
        self._send_otp_email(user.email, otp.otp, user.first_name or user.username)

        return user

    @staticmethod
    def _send_otp_email(email: str, otp_code: str, name: str) -> None:
        """
        Send the OTP verification email.

        Args:
            email: Recipient email address.
            otp_code: The 6-digit OTP string.
            name: The user's first name or username for personalisation.
        """
        subject = f"MayaTrail — Your verification code is {otp_code}"
        message = (
            f"Hi {name},\n\n"
            f"Your MayaTrail verification code is: {otp_code}\n\n"
            f"This code will expire in "
            f"{getattr(settings, 'OTP_EXPIRY_MINUTES', 10)} minutes.\n\n"
            f"If you did not request this, please ignore this email.\n\n"
            f"— MayaTrail Team"
        )
        from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@mayatrail.tech")
        send_mail(subject, message, from_email, [email], fail_silently=False)


class VerifyOTPSerializer(serializers.Serializer):
    """
    Validates an email + OTP combination to activate a user account.
    """

    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6, min_length=6)

    def validate_email(self, value: str) -> str:
        """Normalise the email to lowercase."""
        return value.lower().strip()

    def validate(self, attrs: dict) -> dict:
        """
        Verify the OTP is correct and still valid.

        On success, activates the user account.

        Raises:
            serializers.ValidationError: If the OTP is invalid, expired,
            or max attempts exceeded.
        """
        email = attrs["email"]
        otp_code = attrs["otp"]

        # Find the most recent unused OTP for this email
        try:
            otp_record = EmailOTP.objects.filter(
                email=email, is_used=False
            ).latest("created_at")
        except EmailOTP.DoesNotExist:
            raise serializers.ValidationError(
                {"otp": "No pending verification found. Please register again."}
            )

        if otp_record.is_expired:
            raise serializers.ValidationError(
                {"otp": "This code has expired. Please request a new one."}
            )

        if not otp_record.is_valid:
            raise serializers.ValidationError(
                {"otp": "Too many attempts. Please request a new code."}
            )

        if not otp_record.verify(otp_code):
            remaining = getattr(settings, "OTP_MAX_ATTEMPTS", 5) - otp_record.attempts
            raise serializers.ValidationError(
                {"otp": f"Invalid code. {remaining} attempt(s) remaining."}
            )

        # Activate the user
        try:
            user = User.objects.get(email=email, is_active=False)
            user.is_active = True
            user.save(update_fields=["is_active"])
            attrs["user"] = user
        except User.DoesNotExist:
            raise serializers.ValidationError(
                {"email": "No pending registration found for this email."}
            )

        return attrs


class ResendOTPSerializer(serializers.Serializer):
    """
    Validates an email for OTP re-send.  Generates a new OTP and sends it.
    """

    email = serializers.EmailField()

    def validate_email(self, value: str) -> str:
        """Normalise email and check an inactive user exists."""
        normalised = value.lower().strip()
        if not User.objects.filter(email=normalised, is_active=False).exists():
            raise serializers.ValidationError(
                "No pending registration found for this email."
            )
        return normalised

    def create(self, validated_data: dict) -> EmailOTP:
        """Generate a new OTP and send it."""
        email = validated_data["email"]
        user = User.objects.get(email=email, is_active=False)
        otp = EmailOTP.generate_for_email(email)

        name = user.first_name or user.username
        RegisterSerializer._send_otp_email(email, otp.otp, name)

        return otp


class GoogleOAuthSerializer(serializers.Serializer):
    """
    Validates a Google ID token and returns (or creates) the matching user.

    Flow:
        1. The frontend obtains an ID token from Google Identity Services.
        2. It posts that token to /api/auth/google/.
        3. This serializer verifies the token against Google's public keys.
        4. Three cases are handled:
             a. Returning Google user   — match by google_sub, return directly.
             b. Existing credentials user with same email — link google_sub to
                their account and return the user.
             c. Brand-new user — create with is_active=True; no invite code
                required because Google's identity verification provides
                equivalent friction.

    The validated data contains the authenticated user instance under the
    key 'user'.  The view then issues a JWT pair using
    MayaTrailTokenObtainPairSerializer.get_token(user) directly.
    """

    id_token = serializers.CharField(write_only=True)

    def validate_id_token(self, value: str) -> str:
        """Basic presence check; the real validation happens in validate()."""
        if not value:
            raise serializers.ValidationError("ID token is required.")
        return value

    def validate(self, attrs: dict) -> dict:
        """
        Verify the Google ID token and resolve the user account.

        Args:
            attrs: Validated field values containing 'id_token'.

        Returns:
            attrs with 'user' key set to the resolved User instance.

        Raises:
            serializers.ValidationError: If the token is invalid, the
            Google client ID is not configured, or account resolution fails.
        """
        client_id = getattr(settings, "GOOGLE_CLIENT_ID", "")
        if not client_id:
            raise serializers.ValidationError(
                "Google OAuth is not configured on this server."
            )

        raw_token = attrs["id_token"]

        try:
            payload = google_id_token.verify_oauth2_token(
                raw_token,
                google_requests.Request(),
                client_id,
            )
        except ValueError as exc:
            raise serializers.ValidationError(
                {"id_token": f"Invalid Google ID token: {exc}"}
            )

        google_sub = payload.get("sub")
        email = payload.get("email", "").lower().strip()
        first_name = payload.get("given_name", "")
        last_name = payload.get("family_name", "")

        if not google_sub or not email:
            raise serializers.ValidationError(
                {"id_token": "Token payload is missing required claims (sub, email)."}
            )

        user = self._resolve_user(google_sub, email, first_name, last_name)
        attrs["user"] = user
        return attrs

    @staticmethod
    def _resolve_user(
        google_sub: str,
        email: str,
        first_name: str,
        last_name: str,
    ) -> "User":
        """
        Find an existing user or create a new one for the given Google identity.

        Resolution order:
            1. User with matching google_sub (returning Google SSO user).
            2. Active user with matching email (credentials user — link SSO).
            3. Create a new active user (first-time Google SSO sign-up).

        For case 2 the google_sub is persisted so future logins use case 1.
        For case 3 the password is set to unusable because the user will
        always authenticate via Google; they never need a password.

        Args:
            google_sub: The stable 'sub' claim from the verified ID token.
            email: Normalised email from the token payload.
            first_name: Given name from the token payload (may be empty).
            last_name: Family name from the token payload (may be empty).

        Returns:
            The resolved or newly created User instance.
        """
        # Case 1: returning Google SSO user.
        try:
            return User.objects.get(google_sub=google_sub)
        except User.DoesNotExist:
            pass

        # Case 2: credentials user with the same email — link accounts.
        try:
            user = User.objects.get(email=email, is_active=True)
            user.google_sub = google_sub
            user.save(update_fields=["google_sub"])
            return user
        except User.DoesNotExist:
            pass

        # Case 3: brand-new user via Google SSO.
        username = email.split("@")[0]

        # Ensure the derived username is unique by appending a numeric suffix.
        base_username = username
        counter = 1
        while User.objects.filter(username=username).exists():
            username = f"{base_username}{counter}"
            counter += 1

        user = User.objects.create_user(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            is_active=True,
            google_sub=google_sub,
        )
        user.set_unusable_password()
        user.save(update_fields=["password"])
        return user
