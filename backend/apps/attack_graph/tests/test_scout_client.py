"""
The HTTP client for the Scout scan service.

requests is mocked, so no service runs. What matters is the request each call
sends and that every failure becomes a ScoutServiceError whose message is safe
to show: the scan request carries temporary AWS credentials, and none of them
may reach a message.
"""

from unittest import mock

import requests
from django.test import SimpleTestCase, override_settings

from apps.attack_graph import scout_client

CREDS = {
    "AWS_ACCESS_KEY_ID": "ASIAEXAMPLE",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AWS_SESSION_TOKEN": "session-token-value",
}
SERVICE = override_settings(SCOUT_SERVICE_URL="http://scout:8080/", SCOUT_SERVICE_TOKEN="shared-token")


def _response(status: int, body=None) -> mock.Mock:
    response = mock.Mock(status_code=status)
    if body is None:
        response.json.side_effect = ValueError("no body")
    else:
        response.json.return_value = body
    return response


@SERVICE
class StartScanTests(SimpleTestCase):
    """POST /v1/scans."""

    def test_sends_the_credentials_regions_and_token(self):
        with mock.patch("requests.request", return_value=_response(202, {"scan_id": "abc"})) as call:
            self.assertEqual(scout_client.start_scan(CREDS, ["us-east-1"], narrate_top=25), "abc")
        method, url = call.call_args.args
        self.assertEqual((method, url), ("POST", "http://scout:8080/v1/scans"))
        kwargs = call.call_args.kwargs
        self.assertEqual(kwargs["headers"], {"Authorization": "Bearer shared-token"})
        self.assertEqual(kwargs["json"], {
            "credentials": {
                "access_key_id": "ASIAEXAMPLE",
                "secret_access_key": CREDS["AWS_SECRET_ACCESS_KEY"],
                "session_token": "session-token-value",
            },
            "regions": ["us-east-1"],
            "narrate_top": 25,
        })
        self.assertEqual(kwargs["timeout"], scout_client.REQUEST_TIMEOUT_SECONDS)

    def test_a_busy_service_is_reported_as_busy(self):
        with mock.patch("requests.request", return_value=_response(429, {"error": "at capacity"})):
            with self.assertRaisesMessage(scout_client.ScoutServiceError, "busy"):
                scout_client.start_scan(CREDS, [], narrate_top=25)

    def test_a_refusal_carries_the_service_reason(self):
        with mock.patch("requests.request", return_value=_response(400, {"error": "not an AWS region name: x"})):
            with self.assertRaisesMessage(scout_client.ScoutServiceError, "not an AWS region name: x"):
                scout_client.start_scan(CREDS, ["x"], narrate_top=25)

    def test_an_unreachable_service_never_echoes_the_request(self):
        error = requests.ConnectionError(f"failed sending {CREDS['AWS_SECRET_ACCESS_KEY']}")
        with mock.patch("requests.request", side_effect=error):
            with self.assertRaises(scout_client.ScoutServiceError) as caught:
                scout_client.start_scan(CREDS, [], narrate_top=25)
        self.assertEqual(str(caught.exception), scout_client.UNREACHABLE)
        self.assertIsNone(caught.exception.__cause__)

    @override_settings(SCOUT_SERVICE_TOKEN="")
    def test_no_token_fails_before_any_request(self):
        with mock.patch("requests.request") as call:
            with self.assertRaisesMessage(scout_client.ScoutServiceError, scout_client.NOT_CONFIGURED):
                scout_client.start_scan(CREDS, [], narrate_top=25)
        call.assert_not_called()


@SERVICE
class PollAndDeleteTests(SimpleTestCase):
    """GET and DELETE /v1/scans/<id>."""

    def test_wait_polls_until_the_scan_finishes(self):
        replies = [_response(200, {"status": "queued"}), _response(200, {"status": "running"}),
                   _response(200, {"status": "completed", "report": {}})]
        with mock.patch("requests.request", side_effect=replies) as call, \
                mock.patch("apps.attack_graph.scout_client.time.sleep") as sleep:
            result = scout_client.wait_for_scan("abc")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(call.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(call.call_args.args, ("GET", "http://scout:8080/v1/scans/abc"))

    def test_an_unknown_scan_explains_the_likely_restart(self):
        with mock.patch("requests.request", return_value=_response(404, {"error": "no such scan"})):
            with self.assertRaisesMessage(scout_client.ScoutServiceError, "restarted"):
                scout_client.get_scan("abc")

    def test_delete_ignores_failures(self):
        with mock.patch("requests.request", side_effect=requests.ConnectionError("down")):
            scout_client.delete_scan("abc")

    def test_delete_targets_the_scan(self):
        with mock.patch("requests.request", return_value=_response(204)) as call:
            scout_client.delete_scan("abc")
        self.assertEqual(call.call_args.args, ("DELETE", "http://scout:8080/v1/scans/abc"))
