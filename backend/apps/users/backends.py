"""Authentication backends for MayaTrail."""

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q

User = get_user_model()


class UsernameOrEmailBackend(ModelBackend):
    """Authenticate with either a username or an email address.

    The login form presents a single "Username or Email" field, so the same
    input must be able to resolve a user by either identifier. Django's default
    ModelBackend matches only USERNAME_FIELD (username), which is why an email
    typed into that field fails. This backend widens the lookup to username OR
    email and then defers password verification and the active-user check to
    ModelBackend, so only the account lookup changes, not the security checks.
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        """Resolve the user by username or email, then verify the password.

        Args:
            request: The current request. Unused, kept for the backend contract.
            username: The identifier from the login form (a username or email).
            password: The raw password to verify.

        Returns:
            The authenticated User instance, or None when authentication fails.
        """
        if username is None or password is None:
            return None

        # Username match stays exact (case-sensitive, as Django usernames are);
        # email match is case-insensitive since emails are stored lowercased.
        try:
            user = User.objects.get(Q(username=username) | Q(email__iexact=username))
        except User.DoesNotExist:
            # Run the hasher once so a missing account takes about as long as a
            # wrong password, which avoids leaking account existence via timing.
            User().set_password(password)
            return None
        except User.MultipleObjectsReturned:
            # The input matched one account's username and another's email.
            # Prefer the exact username match so the intended account resolves.
            user = User.objects.filter(username=username).first()
            if user is None:
                return None

        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
