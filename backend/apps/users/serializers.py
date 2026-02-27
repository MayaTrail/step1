"""
Serializers for the users app.

UserSerializer   — read-only representation of the authenticated user.
RegisterSerializer — validates and creates a new user account.
"""

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

    Accepts username, email, and password.  Password is write-only
    and is hashed before storage via create().
    """

    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ["username", "email", "password"]

    def create(self, validated_data: dict) -> User:
        """
        Create and return a new user with a hashed password.

        Args:
            validated_data: Validated field values from the request body.

        Returns:
            The newly created User instance.
        """
        return User.objects.create_user(
            username=validated_data["username"],
            email=validated_data.get("email", ""),
            password=validated_data["password"],
        )
