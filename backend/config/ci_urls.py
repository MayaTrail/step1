"""
Empty URL configuration used only by config.settings.ci.

Django imports ROOT_URLCONF during system checks, and config/urls.py reaches
every app's views, which import their tasks module and therefore pulumi and
boto3. No test in the suite resolves a URL, so an empty pattern list lets the
test run skip that entire dependency chain.
"""

urlpatterns: list = []
