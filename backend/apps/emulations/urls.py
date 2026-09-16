"""
URL routing for the emulations app.

Mounted at /api/emulations/ in config/urls.py.

All routes require IsEnterpriseUser (enforced in each view).

GET  /api/emulations/                                    EmulationListView
GET  /api/emulations/<emulation_type>/estimate/          EmulationEstimateView
GET  /api/emulations/<emulation_type>/techniques/        EmulationTechniquesView
GET  /api/emulations/<emulation_type>/detections/        EmulationDetectionsView
GET  /api/emulations/<emulation_type>/detections/<rule_id>/  EmulationDetectionDetailView
GET  /api/emulations/<emulation_type>/detections/export/ EmulationDetectionExportView
GET  /api/emulations/<emulation_type>/playbook/          EmulationPlaybookView
GET  /api/emulations/library/                            PlaybookLibraryListView
GET  /api/emulations/library/<playbook_id>/              PlaybookLibraryDetailView
GET  /api/emulations/library/<playbook_id>/detections/   PlaybookLibraryDetectionsView
GET  /api/emulations/detection-targets/                  DetectionTargetsView
GET  /api/emulations/coverage-trend/?emulation_type=     CoverageTrendView
GET  /api/emulations/assurance/                          AssuranceSummaryView
GET  /api/emulations/compare/?a=<run_id>&b=<run_id>      RunComparisonView
CRUD /api/emulations/schedules/                          ScheduledRun* views
POST /api/emulations/deploy/                             EmulationDeployView
GET  /api/emulations/runs/?status=<csv>                  EmulationRunListView
GET  /api/emulations/<run_id>/                           EmulationRunDetailView
GET  /api/emulations/<run_id>/detections/export/         RunDetectionExportView
GET  /api/emulations/<run_id>/regressions/               RunRegressionView
GET  /api/emulations/<run_id>/report/                    RunReportView
POST /api/emulations/<stack_id>/attack/                  EmulationAttackView
POST /api/emulations/<stack_id>/destroy/                 EmulationDestroyView

Route ordering note: the string routes (<emulation_type>/...) must come before
the UUID routes (<run_id>/, <stack_id>/...) to prevent the UUID pattern from
greedily matching emulation type strings.
"""

from django.urls import path

from .views import (
    AssuranceSummaryView,
    CoverageTrendView,
    DetectionTargetsView,
    EmulationAttackView,
    EmulationDeployView,
    EmulationDestroyView,
    EmulationDetectionDetailView,
    EmulationDetectionExportView,
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
    RunComparisonView,
    RunDetectionExportView,
    RunRegressionView,
    RunReportView,
    ScheduledRunDetailView,
    ScheduledRunListCreateView,
)

urlpatterns = [
    path("", EmulationListView.as_view(), name="emulation-list"),
    path("deploy/", EmulationDeployView.as_view(), name="emulation-deploy"),

    path("runs/", EmulationRunListView.as_view(), name="emulation-run-list"),
    path("detection-targets/", DetectionTargetsView.as_view(), name="detection-targets"),
    path("coverage-trend/", CoverageTrendView.as_view(), name="coverage-trend"),
    path("assurance/", AssuranceSummaryView.as_view(), name="assurance-summary"),
    path("compare/", RunComparisonView.as_view(), name="run-compare"),
    path("schedules/", ScheduledRunListCreateView.as_view(), name="schedule-list-create"),
    path("schedules/<uuid:schedule_id>/", ScheduledRunDetailView.as_view(), name="schedule-detail"),

    # Standalone playbook library. Literal "library/" must precede the
    # <str:emulation_type>/ routes below or it is swallowed by them.
    path("library/", PlaybookLibraryListView.as_view(), name="playbook-library-list"),
    path("library/<str:playbook_id>/", PlaybookLibraryDetailView.as_view(), name="playbook-library-detail"),
    path("library/<str:playbook_id>/detections/", PlaybookLibraryDetectionsView.as_view(), name="playbook-library-detections"),

    # Before the <str:emulation_type> route below, not after it. <str:> matches
    # a UUID perfectly well, so declaring the emulation export first would send
    # every run export to it and 404 with "unknown emulation <uuid>". The uuid
    # converter cannot match an emulation name, so this ordering is safe in
    # both directions.
    path("<uuid:run_id>/detections/export/", RunDetectionExportView.as_view(), name="run-detection-export"),
    path("<uuid:run_id>/regressions/", RunRegressionView.as_view(), name="run-regressions"),
    path("<uuid:run_id>/report/", RunReportView.as_view(), name="run-report"),

    path("<str:emulation_type>/estimate/", EmulationEstimateView.as_view(), name="emulation-estimate"),
    path("<str:emulation_type>/techniques/", EmulationTechniquesView.as_view(), name="emulation-techniques"),
    path("<str:emulation_type>/detections/", EmulationDetectionsView.as_view(), name="emulation-detections"),
    # Before the <str:rule_id> route below: that pattern would otherwise match
    # "export" and look for a detection rule of that name.
    path("<str:emulation_type>/detections/export/", EmulationDetectionExportView.as_view(), name="emulation-detection-export"),
    path("<str:emulation_type>/detections/<str:rule_id>/", EmulationDetectionDetailView.as_view(), name="emulation-detection-detail"),
    path("<str:emulation_type>/playbook/", EmulationPlaybookView.as_view(), name="emulation-playbook"),
    path("<str:emulation_type>/command/", PlaybookCommandView.as_view(), name="emulation-playbook-command"),

    path("<uuid:run_id>/", EmulationRunDetailView.as_view(), name="emulation-run-detail"),
    path("<uuid:stack_id>/attack/", EmulationAttackView.as_view(), name="emulation-attack"),
    path("<uuid:stack_id>/destroy/", EmulationDestroyView.as_view(), name="emulation-destroy"),
]
