"""
URL routing for the connectors app.

Mounted at /api/connectors/ in config/urls.py.
"""

from django.urls import path

from .views import AWSConnectorView

urlpatterns = [
    path("aws/verify/", AWSConnectorView.as_view(), name="connector-aws-verify"),
]
