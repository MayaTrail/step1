"""
Custom User model and EmailOTP model for MayaTrail.

User: Extends Django's AbstractUser with a unique email constraint and
cloud-connector fields used during the onboarding flow.

EmailOTP: Stores a one-time passcode sent to the user's email during
registration. The OTP expires after a configurable number of minutes.
"""

import random
import string
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    """
    MayaTrail user.

    Inherits all standard Django user fields (username, email, password,
    first_name, last_name, is_staff, is_active, date_joined, etc.).

    The email field is overridden to enforce uniqueness at the database
    level — AbstractUser does not set unique=True by default.

    Onboarding state is tracked by two booleans:
      - is_verified=False, is_demo=False → new user, must visit /connector
      - is_verified=False, is_demo=True  → opted for demo sandbox
      - is_verified=True,  is_demo=False → IAM role verified via STS
    """

    email = models.EmailField("email address", unique=True, blank=False)
    aws_role_arn = models.CharField(
        "AWS IAM Role ARN",
        max_length=256,
        blank=True,
        default="",
        help_text="ARN of the cross-account role MayaTrail assumes.",
    )
    is_verified = models.BooleanField(
        default=False,
        help_text="True when the user's IAM role has been verified via STS.",
    )
    is_demo = models.BooleanField(
        default=False,
        help_text="True when the user opted for demo mode.",
    )
    demo_activated_at = models.DateTimeField(
        null=True,
        blank=True,
        default=None,
        help_text="UTC timestamp when demo mode was activated. Used to compute expiry.",
    )
    demo_used = models.BooleanField(
        default=False,
        help_text="True once the user has ever activated demo mode. Prevents re-activation.",
    )
    google_sub = models.CharField(
        "Google subject ID",
        max_length=256,
        blank=True,
        default="",
        help_text=(
            "Stable Google account identifier (the 'sub' claim from the id_token). "
            "Set when the user authenticates via Google OAuth. "
            "Used to look up returning Google users without relying on email alone."
        ),
    )

    class Meta:
        verbose_name = "user"
        verbose_name_plural = "users"
        db_table = "users"

    def __str__(self) -> str:
        """Return the username as the string representation."""
        return self.username

    @property
    def auth_method(self) -> str:
        """Return the authentication method used to create this account."""
        return "google_sso" if self.google_sub else "credentials"

    @property
    def is_demo_expired(self) -> bool:
        """Return True if the user's demo session has exceeded the allowed duration."""
        if not self.is_demo or not self.demo_activated_at:
            return False
        duration = getattr(settings, "DEMO_DURATION_MINUTES", 5)
        return timezone.now() > self.demo_activated_at + timedelta(minutes=duration)

    @property
    def demo_expires_at(self):
        """Return the datetime when the demo session expires, or None."""
        if not self.is_demo or not self.demo_activated_at:
            return None
        duration = getattr(settings, "DEMO_DURATION_MINUTES", 5)
        return self.demo_activated_at + timedelta(minutes=duration)


class EmailOTP(models.Model):
    """
    One-time passcode for email verification during registration.

    A 6-digit OTP is generated and associated with an email address.
    The OTP expires after OTP_EXPIRY_MINUTES (default: 10 minutes).
    A max of OTP_MAX_ATTEMPTS (default: 5) verification attempts
    are allowed per OTP before it is considered invalid.
    """

    email = models.EmailField(db_index=True)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    attempts = models.PositiveSmallIntegerField(default=0)
    is_used = models.BooleanField(default=False)

    class Meta:
        verbose_name = "email OTP"
        verbose_name_plural = "email OTPs"
        db_table = "email_otps"
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"OTP for {self.email} (expires {self.expires_at})"

    @property
    def is_expired(self) -> bool:
        """Return True if the OTP has passed its expiry time."""
        return timezone.now() > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Return True if the OTP has not been used, is not expired, and
        has not exceeded max attempts."""
        max_attempts = getattr(settings, "OTP_MAX_ATTEMPTS", 5)
        return not self.is_used and not self.is_expired and self.attempts < max_attempts

    def verify(self, code: str) -> bool:
        """
        Attempt to verify the given code against this OTP.

        Increments the attempt counter regardless of success.
        Marks the OTP as used on success.

        Args:
            code: The 6-digit OTP string entered by the user.

        Returns:
            True if the code matches and the OTP is still valid.
        """
        self.attempts += 1
        self.save(update_fields=["attempts"])

        if not self.is_valid:
            return False

        if self.otp != code:
            return False

        self.is_used = True
        self.save(update_fields=["is_used"])
        return True

    @classmethod
    def generate_for_email(cls, email: str) -> "EmailOTP":
        """
        Create a new OTP for the given email address.

        Invalidates any previous unused OTPs for the same email by
        marking them as used.

        Args:
            email: The email address to associate the OTP with.

        Returns:
            The newly created EmailOTP instance.
        """
        # Invalidate any existing unused OTPs for this email
        cls.objects.filter(email=email, is_used=False).update(is_used=True)

        expiry_minutes = getattr(settings, "OTP_EXPIRY_MINUTES", 10)
        otp_code = "".join(random.choices(string.digits, k=6))

        return cls.objects.create(
            email=email,
            otp=otp_code,
            expires_at=timezone.now() + timedelta(minutes=expiry_minutes),
        )
