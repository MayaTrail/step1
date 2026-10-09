"""
URL routing for the connectors app.

Mounted at /api/connectors/ in config/urls.py.
"""

from django.urls import path

from .views import AWSAuditConnectorView, AWSConnectorView

urlpatterns = [
    path("aws/verify/", AWSConnectorView.as_view(), name="connector-aws-verify"),
    path("aws/audit/", AWSAuditConnectorView.as_view(), name="connector-aws-audit"),
]
