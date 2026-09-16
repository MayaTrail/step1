"""
URL routing for the playbooks app.

Mounted at /api/playbooks/ in config/urls.py.

GET    /api/playbooks/              list playbooks visible to the caller
POST   /api/playbooks/              author a new playbook
POST   /api/playbooks/fork/         fork an emulation's shipped PLAYBOOK.md
POST   /api/playbooks/generate/     draft one with the user's LLM connector
GET    /api/playbooks/<id>/         read one
PATCH  /api/playbooks/<id>/         edit one (owner only)
DELETE /api/playbooks/<id>/         delete one (owner only)
GET    /api/playbooks/<id>/export/  download as PLAYBOOK.md

Route ordering note: 'fork/' is declared before '<uuid:pk>/' so the literal
route wins. With the uuid converter it would not actually collide, but the
ordering matches the convention in apps/emulations/urls.py and survives anyone
loosening the converter later.
"""

from django.urls import path

from .views import (
    PlaybookDetailView,
    PlaybookExportView,
    PlaybookForkView,
    PlaybookGenerateView,
    PlaybookListCreateView,
)

app_name = "playbooks"

urlpatterns = [
    path("", PlaybookListCreateView.as_view(), name="list-create"),
    path("fork/", PlaybookForkView.as_view(), name="fork"),
    path("generate/", PlaybookGenerateView.as_view(), name="generate"),
    path("<uuid:pk>/", PlaybookDetailView.as_view(), name="detail"),
    path("<uuid:pk>/export/", PlaybookExportView.as_view(), name="export"),
]
