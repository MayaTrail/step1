"""
Views for the playbooks app.

GET    /api/playbooks/              PlaybookListCreateView   list visible playbooks
POST   /api/playbooks/              PlaybookListCreateView   author a new one
GET    /api/playbooks/<id>/         PlaybookDetailView       read one
PATCH  /api/playbooks/<id>/         PlaybookDetailView       edit (owner only)
DELETE /api/playbooks/<id>/         PlaybookDetailView       delete (owner only)
POST   /api/playbooks/fork/         PlaybookForkView         fork a shipped PLAYBOOK.md
GET    /api/playbooks/<id>/export/  PlaybookExportView       download as PLAYBOOK.md
POST   /api/playbooks/generate/    PlaybookGenerateView     draft one with the LLM

All routes require IsEnterpriseUser, matching the rest of the API.

Route ordering note: 'fork/' must come before '<uuid:pk>/' in urls.py or the
UUID converter never gets the chance to reject it.
"""

from __future__ import annotations

import logging
import re

from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import BasePermission
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.infrastructure.permissions import IsEnterpriseUser

from .models import Playbook
from .generation import generate_playbook
from .serializers import (
    PlaybookForkSerializer,
    PlaybookGenerateSerializer,
    PlaybookListSerializer,
    PlaybookSerializer,
)
from .sources import PlaybookSourceError, load_shipped_playbook

logger = logging.getLogger(__name__)


class IsOwner(BasePermission):
    """Object-level check: only the author may modify or delete a playbook."""

    message = "You can only modify playbooks you created."

    def has_object_permission(self, request: Request, view, obj: Playbook) -> bool:
        """Return True when the requesting user owns the playbook."""
        return obj.owner_id == request.user.id


def _visible_to(user) -> "models.QuerySet[Playbook]":
    """
    Playbooks this user may read.

    Their own, plus anything shared at organisation level. There is no
    Organization model yet, so organisation-visible currently means visible to
    every enterprise user; when organisations land this gains one filter and
    nothing else in the app changes.
    """
    return (
        Playbook.objects
        .filter(Q(owner=user) | Q(visibility=Playbook.Visibility.ORGANIZATION))
        .select_related("owner")
    )


class PlaybookListCreateView(APIView):
    """List the playbooks a user can see, or author a new one."""

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request) -> Response:
        """
        Return playbooks visible to the caller, newest edit first.

        Query params:
            mine=1                 only the caller's own playbooks
            source=<emulation>     only forks of that emulation package
        """
        qs = _visible_to(request.user)

        if request.query_params.get("mine") in ("1", "true", "yes"):
            qs = qs.filter(owner=request.user)

        source = request.query_params.get("source")
        if source:
            qs = qs.filter(source_emulation=source)

        return Response(PlaybookListSerializer(qs, many=True).data)

    def post(self, request: Request) -> Response:
        """Create a playbook owned by the caller."""
        serializer = PlaybookSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # source_emulation is only set by the fork endpoint; a hand-rolled POST
        # claiming to be a fork of something would be a lie on the card.
        playbook = serializer.save(owner=request.user, source_emulation="")
        return Response(
            PlaybookSerializer(playbook).data,
            status=status.HTTP_201_CREATED,
        )


class PlaybookDetailView(APIView):
    """Read, edit or delete a single playbook."""

    permission_classes = [IsEnterpriseUser]

    def _get(self, request: Request, pk, *, for_write: bool) -> Playbook:
        """Fetch a playbook, enforcing read visibility and write ownership."""
        playbook = get_object_or_404(_visible_to(request.user), pk=pk)
        if for_write:
            checker = IsOwner()
            if not checker.has_object_permission(request, self, playbook):
                self.permission_denied(request, message=checker.message)
        return playbook

    def get(self, request: Request, pk) -> Response:
        """Return the full playbook."""
        return Response(PlaybookSerializer(self._get(request, pk, for_write=False)).data)

    def patch(self, request: Request, pk) -> Response:
        """Apply a partial update. Owner only."""
        playbook = self._get(request, pk, for_write=True)
        serializer = PlaybookSerializer(playbook, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    def delete(self, request: Request, pk) -> Response:
        """Delete the playbook. Owner only."""
        self._get(request, pk, for_write=True).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class PlaybookForkView(APIView):
    """
    Fork the PLAYBOOK.md that ships with an emulation into an editable copy.

    POST /api/playbooks/fork/
    Body: { "emulation_type": "ambersquid", "title": "AMBERSQUID - our response" }
    """

    permission_classes = [IsEnterpriseUser]

    def post(self, request: Request) -> Response:
        """Create a playbook seeded from a shipped one."""
        serializer = PlaybookForkSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        emulation_type = serializer.validated_data["emulation_type"]

        try:
            display_name, markdown = load_shipped_playbook(emulation_type)
        except PlaybookSourceError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_404_NOT_FOUND)

        title = (serializer.validated_data.get("title") or "").strip()
        if not title:
            title = "%s - our response" % display_name

        playbook = Playbook.objects.create(
            owner=request.user,
            title=title[:200],
            body=markdown,
            summary="Forked from the %s playbook." % display_name,
            source_emulation=emulation_type,
        )
        return Response(
            PlaybookSerializer(playbook).data,
            status=status.HTTP_201_CREATED,
        )


class PlaybookExportView(APIView):
    """
    Download a playbook as a PLAYBOOK.md file.

    GET /api/playbooks/<id>/export/

    The stored body is already Markdown, so this is the same document the
    emulation packages carry - it can be dropped straight into a detection repo.
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request, pk) -> HttpResponse:
        """Return the playbook body as a Markdown attachment."""
        playbook = get_object_or_404(_visible_to(request.user), pk=pk)

        # Content-Disposition is header-injection sensitive, so build the
        # filename from the slug rather than the user-supplied title.
        stem = re.sub(r"[^a-z0-9-]", "", playbook.slug) or "playbook"
        response = HttpResponse(playbook.body, content_type="text/markdown; charset=utf-8")
        response["Content-Disposition"] = 'attachment; filename="%s.md"' % stem
        return response


class PlaybookGenerateView(APIView):
    """
    Draft a playbook with the user's configured LLM connector.

    POST /api/playbooks/generate/
    Body: {
        "brief": "Someone created an IAM user outside the change window...",
        "reference_urls": ["https://..."],       # cited, never fetched
        "reference_text": "...pasted advisory..."  # optional
    }

    Returns the Markdown body and a set of review notes. Nothing is persisted:
    the draft lands in the editor, and the author saves it if they want it.
    That split is deliberate - a generated playbook should not exist as a
    saved artefact until a person has looked at it.

    Shares the 'ai_chat' throttle scope with the rest of the AI surface so a
    user cannot turn their connector into an unbounded spend through this
    route.
    """

    permission_classes = [IsEnterpriseUser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "ai_chat"

    def post(self, request: Request) -> Response:
        """Draft one playbook body and return it unsaved."""
        serializer = PlaybookGenerateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # Imported here: apps.ai.views pulls in boto3 for the Bedrock STS path,
        # and this app must stay importable without it (see sources.py).
        from apps.ai.models import LLMConnector
        from apps.ai.views import build_credentials

        connector = LLMConnector.objects.filter(user=request.user).first()
        if connector is None or not connector.enabled:
            return Response(
                {
                    "detail": "No active AI connector. Add one in "
                              "Settings -> AI Assistant to draft with AI."
                },
                status=status.HTTP_409_CONFLICT,
            )

        creds, error = build_credentials(request.user, connector)
        if error:
            return Response({"detail": error}, status=status.HTTP_409_CONFLICT)

        result = generate_playbook(
            connector.provider,
            creds,
            connector.model,
            brief=data["brief"],
            reference_urls=data.get("reference_urls") or [],
            reference_text=data.get("reference_text") or "",
        )
        if "error" in result:
            return Response({"detail": result["error"]}, status=status.HTTP_502_BAD_GATEWAY)

        return Response(result)
