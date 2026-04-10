"""
Serializers for the connectors app.

AWSConnectorSerializer — validates a submitted AWS IAM role ARN.
"""

import re

from rest_framework import serializers

# Regex for validating AWS IAM role ARNs
# Format: arn:aws:iam::<12-digit-account-id>:role/<role-name>
_ARN_RE = re.compile(r"^arn:aws:iam::\d{12}:role/[\w+=,.@/-]+$")


class AWSConnectorSerializer(serializers.Serializer):
    """
    Validates the IAM role ARN submitted on the connector page.

    The ARN must match the standard format:
    arn:aws:iam::<12-digit-account-id>:role/<role-name>
    """

    role_arn = serializers.CharField(max_length=256)

    def validate_role_arn(self, value: str) -> str:
        """
        Ensure the ARN looks like a valid IAM role ARN.

        This is a format check only — actual verification is done
        via STS AssumeRole in the view.

        Args:
            value: The role ARN string from the request body.

        Returns:
            The ARN unchanged if the pattern matches.

        Raises:
            serializers.ValidationError: If the format is invalid.
        """
        if not _ARN_RE.match(value.strip()):
            raise serializers.ValidationError(
                "Invalid ARN format. Expected: arn:aws:iam::<account-id>:role/<role-name>"
            )
        return value.strip()
