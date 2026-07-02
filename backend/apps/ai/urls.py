"""URL routes for the ai app, mounted at /api/ai/."""

from django.urls import path

from .views import (
    ConversationDetailView,
    ConversationListCreateView,
    ConversationMessagesView,
    DetectionValidateView,
    LLMConnectorTestView,
    LLMConnectorView,
)

urlpatterns = [
    path("connector/", LLMConnectorView.as_view(), name="ai-connector"),
    path("connector/test/", LLMConnectorTestView.as_view(), name="ai-connector-test"),
    path(
        "detections/<str:emulation_type>/<str:rule_id>/validate/",
        DetectionValidateView.as_view(),
        name="ai-detection-validate",
    ),
    path("conversations/", ConversationListCreateView.as_view(), name="ai-conversations"),
    path("conversations/<uuid:conversation_id>/", ConversationDetailView.as_view(), name="ai-conversation-detail"),
    path(
        "conversations/<uuid:conversation_id>/messages/",
        ConversationMessagesView.as_view(),
        name="ai-conversation-messages",
    ),
]
