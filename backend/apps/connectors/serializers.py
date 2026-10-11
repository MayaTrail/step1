"""
Serializers for the connectors app.

AWSConnectorSerializer — validates a submitted AWS IAM role ARN.
"""

import re

from rest_framework import serializers

# Regex for validating AWS IAM role ARNs
# Format: arn:aws:iam::<12-digit-account-id>:role/<role-name>
_ARN_RE = re.compile(r"^arn:aws:iam::\d{12}:role/[\w+=,.@/-]+$")

# AWS region ids: "us-east-1", "ap-south-1", "us-gov-west-1", "cn-north-1".
_REGION_RE = re.compile(r"^[a-z]{2}-[a-z-]+-\d$")


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


class AWSAuditConnectorSerializer(serializers.Serializer):
    """
    Validates the read-only audit role ARN, and the regions it may collect
    resources from, submitted for Scout.

    The role's ARN format check is identical to AWSConnectorSerializer's and
    deliberately a separate class: these two ARNs mean different things, and
    a shared serializer is how a future field on one quietly appears on the
    other.

    ``regions`` is tenant-declared, not auto-detected: this is an
    authenticated, consented scan, not adversarial reconnaissance, so there
    is no reason to probe for the account's footprint instead of asking.
    Optional and empty by default — an unset list means the scan stays
    IAM-only, which is today's behaviour, so an already-connected tenant who
    never visits this field again is unaffected.
    """

    role_arn = serializers.CharField(max_length=256)
    regions = serializers.ListField(
        child=serializers.CharField(max_length=20), required=False, default=list,
    )

    def validate_role_arn(self, value: str) -> str:
        """
        Ensure the ARN looks like a valid IAM role ARN.

        Format only — assumability and the IAM read permission are both
        verified against AWS in the view.

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

    def validate_regions(self, value: list[str]) -> list[str]:
        """Reject anything that is not a plausible AWS region id, de-duplicated."""
        deduped = sorted(set(value))
        for region in deduped:
            if not _REGION_RE.match(region):
                raise serializers.ValidationError(
                    f"'{region}' is not a valid AWS region id (e.g. 'ap-south-1')."
                )
        return deduped
