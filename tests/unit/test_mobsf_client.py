"""MobSF client helpers - report readiness and timeout policy."""

from sudarshan_core.services.mobsf_client import MobSFClient


def test_report_ready_requires_identity_or_permissions():
    assert MobSFClient._report_ready({}) is False
    assert MobSFClient._report_ready({"package_name": "com.example.app"}) is True
    assert MobSFClient._report_ready({"permissions": {"android.permission.INTERNET": {}}}) is True
