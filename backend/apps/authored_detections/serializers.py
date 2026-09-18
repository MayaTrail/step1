"""Serializers for the authored_detections app."""

from rest_framework import serializers

from .generation import MAX_BRIEF_CHARS, MAX_REFERENCE_CHARS, MAX_REFERENCE_URLS
from .models import AuthoredDetection

# A Sigma rule is a small document; this cap stops a runaway paste.
MAX_SIGMA_BYTES = 64 * 1024


class AuthoredDetectionListSerializer(serializers.ModelSerializer):
    """A rule without its Sigma body, for list responses."""

    is_generated = serializers.BooleanField(read_only=True)
    owner_username = serializers.CharField(source="owner.username", read_only=True)

    class Meta:
        model = AuthoredDetection
        fields = [
            "id", "title", "slug", "summary", "technique_id", "origin",
            "is_generated", "status", "visibility", "last_fidelity",
            "owner_username", "created_at", "updated_at",
        ]
        read_only_fields = fields


class AuthoredDetectionSerializer(serializers.ModelSerializer):
    """Full rule record, including the Sigma body."""

    is_generated = serializers.BooleanField(read_only=True)
    owner_username = serializers.CharField(source="owner.username", read_only=True)

    class Meta:
        model = AuthoredDetection
        fields = [
            "id", "title", "slug", "summary", "technique_id", "sigma", "origin",
            "is_generated", "status", "visibility", "last_fidelity",
            "owner_username", "created_at", "updated_at",
        ]
        read_only_fields = [
            "id", "slug", "is_generated", "last_fidelity", "owner_username",
            "created_at", "updated_at",
        ]

    def validate_title(self, value: str) -> str:
        """Reject a blank title."""
        title = value.strip()
        if not title:
            raise serializers.ValidationError("Title cannot be blank.")
        return title

    def validate_sigma(self, value: str) -> str:
        """Cap the rule size."""
        if len(value.encode("utf-8")) > MAX_SIGMA_BYTES:
            raise serializers.ValidationError(
                "Rule is larger than %d KB." % (MAX_SIGMA_BYTES // 1024)
            )
        return value


class DetectionGenerateSerializer(serializers.Serializer):
    """Request body for POST /api/detections/authored/generate/."""

    brief = serializers.CharField(max_length=MAX_BRIEF_CHARS)
    technique_id = serializers.CharField(max_length=32, required=False, allow_blank=True)
    reference_urls = serializers.ListField(
        child=serializers.URLField(max_length=500),
        required=False,
        allow_empty=True,
        max_length=MAX_REFERENCE_URLS,
    )
    reference_text = serializers.CharField(
        required=False, allow_blank=True, max_length=MAX_REFERENCE_CHARS
    )

    def validate_brief(self, value: str) -> str:
        """A three-word brief produces a worthless rule."""
        brief = value.strip()
        if len(brief) < 20:
            raise serializers.ValidationError(
                "Describe the behaviour to detect in a sentence or two."
            )
        return brief


class DetectionValidateSerializer(serializers.Serializer):
    """Request body for validating ad-hoc Sigma (before it is saved)."""

    sigma = serializers.CharField(max_length=MAX_SIGMA_BYTES)
