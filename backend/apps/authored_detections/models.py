"""
Models for the authored_detections app.

AuthoredDetection — a Sigma detection rule a user wrote or generated, as opposed
to the read-only rules that ship inside the emulation packages
(apps/emulations/detections.py). This is the writable counterpart: the store the
"generate a detection with AI" feature needs, and where an engineer keeps a rule
they are still tuning before it goes into their SIEM.

`sigma` holds Sigma YAML, the same format the shipped rules and the SIEM
converter (apps/emulations/sigma_convert.py) already speak, so an authored rule
is a first-class citizen: it validates through the same evaluator, exports
through the same converter, and reads through the same renderers. Keeping the
format identical is what makes the generate -> validate -> export loop possible
without a second code path.
"""

import uuid

from django.conf import settings
from django.db import models
from django.utils.text import slugify


class AuthoredDetection(models.Model):
    """A user-authored or AI-generated Sigma detection rule."""

    class Status(models.TextChoices):
        """Authoring state."""

        DRAFT = "draft", "Draft"
        PUBLISHED = "published", "Published"

    class Visibility(models.TextChoices):
        """Who can read this rule."""

        PRIVATE = "private", "Private to the author"
        ORGANIZATION = "organization", "Everyone in the author's organisation"

    class Origin(models.TextChoices):
        """How the rule first came to exist."""

        MANUAL = "manual", "Written by hand"
        GENERATED = "generated", "Drafted by AI"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="authored_detections",
        help_text="The user who created this rule.",
    )
    title = models.CharField(
        max_length=200,
        help_text="Display name, e.g. 'CloudTrail StopLogging outside change window'.",
    )
    slug = models.SlugField(max_length=220, blank=True)
    technique_id = models.CharField(
        max_length=32,
        blank=True,
        default="",
        db_index=True,
        help_text="Primary MITRE technique this rule targets, e.g. 'T1562.008'.",
    )
    sigma = models.TextField(
        blank=True,
        default="",
        help_text="The detection rule, as Sigma YAML.",
    )
    summary = models.CharField(
        max_length=400,
        blank=True,
        default="",
        help_text="One-line description shown on the rule card.",
    )
    status = models.CharField(
        max_length=16, choices=Status.choices, default=Status.DRAFT, db_index=True
    )
    visibility = models.CharField(
        max_length=16,
        choices=Visibility.choices,
        default=Visibility.PRIVATE,
        db_index=True,
    )
    origin = models.CharField(
        max_length=16, choices=Origin.choices, default=Origin.MANUAL
    )
    # The last fidelity score this rule earned from a validation pass, 0..1, or
    # null if never validated. Stored so the card can show "not yet validated"
    # vs a real number without re-running the (paid) LLM synthesis every list.
    last_fidelity = models.FloatField(null=True, blank=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "authored_detections"
        ordering = ["-updated_at"]
        indexes = [models.Index(fields=["owner", "-updated_at"])]

    def __str__(self) -> str:
        """Return the title as the string representation."""
        return self.title

    def save(self, *args, **kwargs):
        """Derive the slug from the title before saving."""
        self.slug = slugify(self.title)[:220]
        super().save(*args, **kwargs)

    @property
    def is_generated(self) -> bool:
        """True when the rule was first drafted by AI."""
        return self.origin == self.Origin.GENERATED
