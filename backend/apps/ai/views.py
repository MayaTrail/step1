"""
Views for the ai app. All endpoints require IsEnterpriseUser.

GET    /api/ai/connector/        LLMConnectorView      current connector (masked)
PUT    /api/ai/connector/        LLMConnectorView      create or update (upsert)
DELETE /api/ai/connector/        LLMConnectorView      remove it
POST   /api/ai/connector/test/   LLMConnectorTestView  validate a key (rate-limited)
GET    /api/ai/conversations/    ConversationListCreateView   list (filter ?emulation_type=)
POST   /api/ai/conversations/    ConversationListCreateView   create a conversation
GET    /api/ai/conversations/<id>/            ConversationDetailView   fetch with messages
DELETE /api/ai/conversations/<id>/            ConversationDetailView   delete
POST   /api/ai/conversations/<id>/messages/   ConversationMessagesView streaming chat turn
"""

import logging

from cryptography.fernet import InvalidToken
from django.http import StreamingHttpResponse
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.emulations.registry import get_emulation
from apps.infrastructure.permissions import IsEnterpriseUser

from . import crypto
from .crypto import EncryptionNotConfigured
from .models import Conversation, LLMConnector, Message
from .prompts import build_chat_system
from .providers import STREAM_ERROR_PREFIX, stream_chat, test_connection
from .serializers import (
    ConversationListSerializer,
    ConversationSerializer,
    LLMConnectorSerializer,
)

logger = logging.getLogger(__name__)

# Multi-turn chat: response token ceiling and the sliding window of prior turns
# forwarded to the provider (bounds prompt size, cost, and context drift).
CHAT_MAX_TOKENS = 1024
CHAT_HISTORY_TURNS = 12


class LLMConnectorView(APIView):
    """Manage the requesting user's LLM connector (one per user)."""

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request) -> Response:
        """Return the current connector (masked), or an empty shape if none."""
        connector = LLMConnector.objects.filter(user=request.user).first()
        if connector is None:
            return Response({"has_key": False, "provider": None, "model": None, "enabled": False})
        return Response(LLMConnectorSerializer(connector).data)

    def put(self, request: Request) -> Response:
        """
        Create or update the user's connector.

        An api_key is required to create; on update it is optional (the existing
        key is kept when no new one is supplied). The key is encrypted before
        storage and never echoed back.
        """
        connector = LLMConnector.objects.filter(user=request.user).first()
        serializer = LLMConnectorSerializer(
            instance=connector, data=request.data, partial=connector is not None
        )
        serializer.is_valid(raise_exception=True)
        data = dict(serializer.validated_data)

        api_key = data.pop("api_key", None)
        if connector is None and not api_key:
            return Response(
                {"api_key": ["An API key is required to create a connector."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if api_key:
            try:
                data["api_key_encrypted"] = crypto.encrypt(api_key)
            except EncryptionNotConfigured as exc:
                logger.error("AI connector save failed: %s", exc)
                return Response(
                    {"detail": "Server is not configured for key storage (LLM_FERNET_KEY missing)."},
                    status=status.HTTP_503_SERVICE_UNAVAILABLE,
                )
            data["key_hint"] = api_key[-4:]

        if connector is None:
            connector = LLMConnector.objects.create(user=request.user, **data)
            created = True
        else:
            for field, value in data.items():
                setattr(connector, field, value)
            connector.save()
            created = False

        logger.info(
            "AI connector %s: user=%s provider=%s model=%s",
            "created" if created else "updated",
            request.user.username, connector.provider, connector.model,
        )
        return Response(
            LLMConnectorSerializer(connector).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    def delete(self, request: Request) -> Response:
        """Delete the user's connector (and its stored key)."""
        deleted, _ = LLMConnector.objects.filter(user=request.user).delete()
        if deleted:
            logger.info("AI connector deleted: user=%s", request.user.username)
        return Response(status=status.HTTP_204_NO_CONTENT)


class LLMConnectorTestView(APIView):
    """
    Validate an LLM connection without billing.

    Body may carry {"provider", "api_key"} to test a key before saving; if
    omitted, the stored connector is tested. Rate-limited via the 'ai_test' scope.
    """

    permission_classes = [IsEnterpriseUser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "ai_test"

    def post(self, request: Request) -> Response:
        """Run the connection test and return {ok, detail}."""
        provider = request.data.get("provider")
        api_key = request.data.get("api_key")

        if not api_key:
            connector = LLMConnector.objects.filter(user=request.user).first()
            if connector is None:
                return Response(
                    {"detail": "No connector configured and no api_key provided."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            provider = connector.provider
            try:
                api_key = crypto.decrypt(connector.api_key_encrypted)
            except (InvalidToken, EncryptionNotConfigured):
                return Response({"ok": False, "detail": "Stored key could not be decrypted."})

        ok, detail = test_connection(provider, api_key)
        return Response({"ok": ok, "detail": detail})


class ConversationListCreateView(APIView):
    """List the user's conversations (optionally for one emulation) or create one."""

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request) -> Response:
        """Return the user's conversations, newest first; filter by ?emulation_type=."""
        queryset = Conversation.objects.filter(user=request.user)
        emulation_type = request.query_params.get("emulation_type")
        if emulation_type:
            queryset = queryset.filter(emulation_type=emulation_type)
        return Response(ConversationListSerializer(queryset, many=True).data)

    def post(self, request: Request) -> Response:
        """Create a new (empty) conversation for an emulation."""
        emulation_type = (request.data.get("emulation_type") or "").strip()
        if not emulation_type:
            return Response(
                {"detail": "emulation_type is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if get_emulation(emulation_type) is None:
            return Response(
                {"detail": f"Unknown emulation '{emulation_type}'."},
                status=status.HTTP_404_NOT_FOUND,
            )
        conversation = Conversation.objects.create(
            user=request.user, emulation_type=emulation_type
        )
        return Response(
            ConversationSerializer(conversation).data, status=status.HTTP_201_CREATED
        )


class ConversationDetailView(APIView):
    """Fetch a conversation with its messages, or delete it."""

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request, conversation_id: str) -> Response:
        """Return the conversation and its full message history."""
        conversation = get_object_or_404(
            Conversation, id=conversation_id, user=request.user
        )
        return Response(ConversationSerializer(conversation).data)

    def delete(self, request: Request, conversation_id: str) -> Response:
        """Delete the conversation and its messages."""
        conversation = get_object_or_404(
            Conversation, id=conversation_id, user=request.user
        )
        conversation.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ConversationMessagesView(APIView):
    """
    Append a user turn and stream the assistant's grounded reply.

    POST /api/ai/conversations/<id>/messages/   Body: {"content": "..."}

    Returns a text/plain stream of response deltas. The assistant turn is saved
    once the stream completes successfully; nothing is saved on a provider error.
    Grounding is rebuilt server-side from the emulation MANIFEST every call.
    """

    permission_classes = [IsEnterpriseUser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "ai_chat"

    def post(self, request: Request, conversation_id: str):
        """Persist the user message and stream the assistant response."""
        conversation = get_object_or_404(
            Conversation, id=conversation_id, user=request.user
        )
        content = (request.data.get("content") or "").strip()
        if not content:
            return Response(
                {"detail": "content is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        entry = get_emulation(conversation.emulation_type)
        if entry is None:
            return Response(
                {"detail": f"Unknown emulation '{conversation.emulation_type}'."},
                status=status.HTTP_404_NOT_FOUND,
            )

        connector = LLMConnector.objects.filter(user=request.user).first()
        if connector is None or not connector.enabled:
            return Response(
                {"detail": "No active LLM connector. Connect one in Settings -> AI Assistant."},
                status=status.HTTP_409_CONFLICT,
            )
        try:
            api_key = crypto.decrypt(connector.api_key_encrypted)
        except (InvalidToken, EncryptionNotConfigured):
            return Response(
                {"detail": "Stored key could not be decrypted."},
                status=status.HTTP_409_CONFLICT,
            )

        # Persist the user's turn; seed the title from the first message.
        if not conversation.title:
            conversation.title = content[:60]
        Message.objects.create(
            conversation=conversation, role=Message.Role.USER, content=content
        )
        conversation.save(update_fields=["title", "updated_at"])

        # Rebuild grounding and the capped sliding window of recent turns.
        system = build_chat_system(entry)
        recent = list(conversation.messages.order_by("-created_at")[:CHAT_HISTORY_TURNS])
        history = [{"role": m.role, "content": m.content} for m in reversed(recent)]

        provider, model = connector.provider, connector.model
        username = request.user.username
        conversation_id_str = str(conversation.id)

        def streamer():
            """Yield response deltas; persist the assistant turn on success."""
            chunks: list[str] = []
            for chunk in stream_chat(
                provider, api_key, model, system, history, max_tokens=CHAT_MAX_TOKENS
            ):
                if chunk.startswith(STREAM_ERROR_PREFIX):
                    detail = chunk[len(STREAM_ERROR_PREFIX):]
                    logger.info(
                        "Chat stream error: user=%s conversation=%s detail=%s",
                        username, conversation_id_str, detail,
                    )
                    yield detail
                    return
                chunks.append(chunk)
                yield chunk
            text = "".join(chunks).strip()
            if text:
                Message.objects.create(
                    conversation=conversation, role=Message.Role.ASSISTANT, content=text
                )
                conversation.save(update_fields=["updated_at"])

        response = StreamingHttpResponse(
            streamer(), content_type="text/plain; charset=utf-8"
        )
        response["X-Accel-Buffering"] = "no"
        response["Cache-Control"] = "no-cache"
        return response
