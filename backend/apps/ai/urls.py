"""URL routes for the ai app, mounted at /api/ai/."""

from django.urls import path

from .views import (
    ConversationDetailView,
    ConversationListCreateView,
    ConversationMessagesView,
    LLMConnectorTestView,
    LLMConnectorView,
)

urlpatterns = [
    path("connector/", LLMConnectorView.as_view(), name="ai-connector"),
    path("connector/test/", LLMConnectorTestView.as_view(), name="ai-connector-test"),
    path("conversations/", ConversationListCreateView.as_view(), name="ai-conversations"),
    path("conversations/<uuid:conversation_id>/", ConversationDetailView.as_view(), name="ai-conversation-detail"),
    path(
        "conversations/<uuid:conversation_id>/messages/",
        ConversationMessagesView.as_view(),
        name="ai-conversation-messages",
    ),
]
