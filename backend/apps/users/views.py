"""
Views for the users app.

RegisterView — creates a new user account (public endpoint).
MeView       — returns the authenticated user's profile (JWT required).
"""

from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import RegisterSerializer, UserSerializer

User = get_user_model()


class RegisterView(APIView):
    """
    Public endpoint for new user registration.

    POST /api/auth/register
    Accepts: { username, email, password }
    Returns: { username, email } on success (201).
    """

    permission_classes = [AllowAny]

    def post(self, request: Request) -> Response:
        """
        Validate registration payload and create a new user.

        Args:
            request: DRF request containing username, email, and password.

        Returns:
            201 Created with serialized user data, or 400 with validation errors.
        """
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class MeView(APIView):
    """
    Returns the profile of the currently authenticated user.

    GET /api/auth/me
    Requires: Bearer JWT token in Authorization header.
    Returns: { id, username, email, first_name, last_name, date_joined }
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
