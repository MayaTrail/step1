"""
Serializers for the users app.

UserSerializer   — read-only representation of the authenticated user.
RegisterSerializer — validates and creates a new user account.
"""

from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """
    Read-only serializer for the User model.

    Exposes a safe subset of fields.  Password is never included.
    """

    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name", "date_joined"]
        read_only_fields = fields


class RegisterSerializer(serializers.ModelSerializer):
    """
    Write serializer used during new account registration.

    Accepts username, email, password, and an invite_code.
    Password is write-only and is hashed before storage via create().
    Email is normalised to lowercase and checked for uniqueness.

    The invite_code field is required when the REGISTRATION_INVITE_CODE
    setting is non-empty.  It is validated but never stored.
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

        This gives a clean validation error instead of a raw DB
        IntegrityError if uniqueness is violated.

        Args:
            value: The raw email string from the request body.

        Returns:
            The lowercased email if it is unique.

        Raises:
            serializers.ValidationError: If the email is already taken.
        """
        normalised = value.lower().strip()
        if User.objects.filter(email=normalised).exists():
            raise serializers.ValidationError(
                "A user with this email already exists."
            )
        return normalised

    def create(self, validated_data: dict) -> User:
        """
        Create and return a new user with a hashed password.

        The invite_code is popped from validated_data since it is a
        gate-check field and is not stored on the User model.

        Args:
            validated_data: Validated field values from the request body.

        Returns:
            The newly created User instance.
        """
        validated_data.pop("invite_code", None)
        return User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
        )
