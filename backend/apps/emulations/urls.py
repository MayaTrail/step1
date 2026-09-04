"""
URL routing for the emulations app.

Mounted at /api/emulations/ in config/urls.py.

All routes require IsEnterpriseUser (enforced in each view).

GET  /api/emulations/                                    EmulationListView
GET  /api/emulations/<emulation_type>/estimate/          EmulationEstimateView
GET  /api/emulations/<emulation_type>/techniques/        EmulationTechniquesView
GET  /api/emulations/<emulation_type>/detections/        EmulationDetectionsView
GET  /api/emulations/<emulation_type>/detections/<rule_id>/  EmulationDetectionDetailView
GET  /api/emulations/<emulation_type>/playbook/          EmulationPlaybookView
GET  /api/emulations/library/                            PlaybookLibraryListView
GET  /api/emulations/library/<playbook_id>/              PlaybookLibraryDetailView
GET  /api/emulations/library/<playbook_id>/detections/   PlaybookLibraryDetectionsView
POST /api/emulations/deploy/                             EmulationDeployView
GET  /api/emulations/runs/?status=<csv>                  EmulationRunListView
GET  /api/emulations/<run_id>/                           EmulationRunDetailView
POST /api/emulations/<stack_id>/attack/                  EmulationAttackView
POST /api/emulations/<stack_id>/destroy/                 EmulationDestroyView

Route ordering note: the string routes (<emulation_type>/...) must come before
the UUID routes (<run_id>/, <stack_id>/...) to prevent the UUID pattern from
greedily matching emulation type strings.
"""

from django.urls import path

from .views import (
    EmulationAttackView,
    EmulationDeployView,
    EmulationDestroyView,
    EmulationDetectionDetailView,
    EmulationDetectionsView,
    EmulationEstimateView,
    EmulationListView,
    EmulationPlaybookView,
    EmulationRunDetailView,
    EmulationRunListView,
    EmulationTechniquesView,
    PlaybookCommandView,
    PlaybookLibraryDetailView,
    PlaybookLibraryDetectionsView,
    PlaybookLibraryListView,
)

urlpatterns = [
    path("", EmulationListView.as_view(), name="emulation-list"),
    path("deploy/", EmulationDeployView.as_view(), name="emulation-deploy"),
    # Literal "runs/" must precede the <uuid:run_id>/ route below.
    path("runs/", EmulationRunListView.as_view(), name="emulation-run-list"),
    # Standalone playbook library. Literal "library/" must precede the
    # <str:emulation_type>/ routes below or it is swallowed by them.
    path("library/", PlaybookLibraryListView.as_view(), name="playbook-library-list"),
    path("library/<str:playbook_id>/", PlaybookLibraryDetailView.as_view(), name="playbook-library-detail"),
    path("library/<str:playbook_id>/detections/", PlaybookLibraryDetectionsView.as_view(), name="playbook-library-detections"),
    # String-param read-only routes — must appear before UUID routes.
    path("<str:emulation_type>/estimate/", EmulationEstimateView.as_view(), name="emulation-estimate"),
    path("<str:emulation_type>/techniques/", EmulationTechniquesView.as_view(), name="emulation-techniques"),
    path("<str:emulation_type>/detections/", EmulationDetectionsView.as_view(), name="emulation-detections"),
    path("<str:emulation_type>/detections/<str:rule_id>/", EmulationDetectionDetailView.as_view(), name="emulation-detection-detail"),
    path("<str:emulation_type>/playbook/", EmulationPlaybookView.as_view(), name="emulation-playbook"),
    path("<str:emulation_type>/command/", PlaybookCommandView.as_view(), name="emulation-playbook-command"),
    # UUID-param lifecycle routes.
    path("<uuid:run_id>/", EmulationRunDetailView.as_view(), name="emulation-run-detail"),
    path("<uuid:stack_id>/attack/", EmulationAttackView.as_view(), name="emulation-attack"),
    path("<uuid:stack_id>/destroy/", EmulationDestroyView.as_view(), name="emulation-destroy"),
]
