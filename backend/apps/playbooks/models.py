"""
Models for the playbooks app.

Playbook — an incident-response runbook authored by a user, either from scratch
           or forked from the PLAYBOOK.md that ships with an emulation package.

Storage format
--------------
`body` holds Markdown, not HTML, even though the editor is a rich-text surface
the user never sees Markdown in. Three reasons:

  * the shipped playbooks are Markdown (emulations/<name>/PLAYBOOK.md), so a
    fork is lossless in and a download is lossless out, and a user playbook
    stays interchangeable with a shipped one;
  * every renderer in the product already reads Markdown (react-markdown +
    remark-gfm drive the read-only viewer), so nothing new is needed to display
    one of these;
  * storing user-submitted HTML and rendering it back is a stored-XSS surface.
    Markdown with raw HTML disabled at render time has no such surface.

An IR playbook is headings, prose, lists, tables, code blocks and links. All of
that survives the round trip, so the constraint costs the author nothing.
"""

import uuid

from django.conf import settings
from django.db import models
from django.utils.text import slugify


class Playbook(models.Model):
    """
    A user-authored incident-response playbook.

    Ownership is by user. There is no Organization model in this codebase yet,
    so `visibility` carries the sharing intent today and the queryset honours
    it; when an Organization lands, an `organization` FK plus a filter change in
    `Playbook.objects.visible_to()` is the whole migration. Nothing in the API
    contract has to move.
    """

    class Visibility(models.TextChoices):
        """Who can read this playbook."""

        PRIVATE = "private", "Private to the author"
        ORGANIZATION = "organization", "Everyone in the author's organisation"

    class Status(models.TextChoices):
        """Authoring state."""

        DRAFT = "draft", "Draft"
        PUBLISHED = "published", "Published"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="playbooks",
        help_text="The user who created this playbook.",
    )
    title = models.CharField(
        max_length=200,
        help_text="Display name, e.g. 'AMBERSQUID — our response'.",
    )
    slug = models.SlugField(
        max_length=220,
        blank=True,
        help_text="URL-safe form of the title. Derived on save; not unique on "
                  "its own because two users may title a playbook the same.",
    )
    body = models.TextField(
        blank=True,
        default="",
        help_text="The playbook itself, as Markdown.",
    )
    summary = models.CharField(
        max_length=400,
        blank=True,
        default="",
        help_text="One-line description shown on the playbook card.",
    )
    source_emulation = models.CharField(
        max_length=64,
        blank=True,
        default="",
        db_index=True,
        help_text=(
            "Emulation package this playbook was forked from, e.g. 'ambersquid'. "
            "Empty when the playbook was authored from scratch."
        ),
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.DRAFT,
        db_index=True,
    )
    visibility = models.CharField(
        max_length=16,
        choices=Visibility.choices,
        default=Visibility.PRIVATE,
        db_index=True,
    )
    is_example = models.BooleanField(
        default=False,
        help_text=(
            "True for the starter playbooks seeded on signup. Purely a UI "
            "label and a signal that this is safe to delete; behaves like any "
            "other playbook otherwise."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "playbooks"
        ordering = ["-updated_at"]
        indexes = [
            models.Index(fields=["owner", "-updated_at"]),
        ]

    def __str__(self) -> str:
        """Return the title as the string representation."""
        return self.title

    def save(self, *args, **kwargs):
        """Derive the slug from the title before saving."""
        self.slug = slugify(self.title)[:220]
        super().save(*args, **kwargs)

    @property
    def is_fork(self) -> bool:
        """True when this playbook started life as a shipped PLAYBOOK.md."""
        return bool(self.source_emulation)
