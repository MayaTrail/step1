"""
Tests for linking attack paths to the emulations that rehearse them.

The catalogue is patched with small hand-written entries, so each test states
exactly which calls an emulation performs and the rule under test is the only
thing that can make it link or not.
"""

import unittest
from unittest import mock

from django.test import SimpleTestCase

from apps.attack_graph.models import ScoutScan
from apps.attack_graph.related import escalation_calls, related_emulations

try:
    from apps.attack_graph.serializers import ScoutScanDetailSerializer
    HAS_DRF = True
except ImportError:  # DRF is not installed under config.settings.ci
    HAS_DRF = False


def _emulation(name, tier, actions, platform="aws"):
    """A registry entry whose single phase performs `actions`."""
    return {
        "name": name,
        "display_name": name.replace("_", " ").title(),
        "tier": tier,
        "platform": platform,
        "attack_path": [{"aws_actions": actions}],
    }


def _chain(chain_id, *sequences):
    """A chain with one step per concrete_api_sequence given."""
    return {"id": chain_id, "steps": [{"concrete_api_sequence": list(seq)} for seq in sequences]}


def _envelope(*chains):
    """A findings envelope holding `chains`."""
    return {"state": "findings", "chains": list(chains)}


class EscalationCallsTests(SimpleTestCase):
    """Reading a path's escalation calls out of Scout's API sequences."""

    def test_keeps_writes_in_order_and_drops_reads_and_setup(self):
        chain = _chain(
            "c1",
            ["iam:UpdateAssumeRolePolicy(RoleName=admin, PolicyDocument=<trust dev>)", "sts:AssumeRole(RoleArn=arn:aws:iam::1:role/admin)"],
            ["iam:GetRole(RoleName=admin)", "iam:CreateAccessKey(UserName=ops)"],
        )
        self.assertEqual(escalation_calls(chain), ["iam:UpdateAssumeRolePolicy", "iam:CreateAccessKey"])

    def test_skips_effects_and_cli_lines(self):
        chain = _chain(
            "c1",
            ["<read IMDS credentials for admin>", "aws ssm get-parameter --name /x", "curl http://169.254.169.254/"],
        )
        self.assertEqual(escalation_calls(chain), [])

    def test_reads_each_part_of_a_semicolon_entry(self):
        chain = _chain("c1", ["sagemaker:CreateModel(...) ; sagemaker:UpdateEndpoint(EndpointName=x)"])
        self.assertEqual(escalation_calls(chain), ["sagemaker:CreateModel", "sagemaker:UpdateEndpoint"])

    def test_does_not_read_arns_inside_arguments_as_calls(self):
        chain = _chain("c1", ["iam:PassRole(RoleArn=arn:aws:iam::1:role/Deploy)"])
        self.assertEqual(escalation_calls(chain), ["iam:PassRole"])

    def test_counts_each_call_once(self):
        chain = _chain("c1", ["iam:CreateAccessKey(UserName=a)"], ["iam:CreateAccessKey(UserName=b)"])
        self.assertEqual(escalation_calls(chain), ["iam:CreateAccessKey"])


@mock.patch("apps.attack_graph.related.list_detection_summaries", return_value=[{}, {}])
class RelatedEmulationsTests(SimpleTestCase):
    """The atomic and campaign rules, ranking, and what never links."""

    def _related(self, catalogue, *chains):
        with mock.patch("apps.attack_graph.related.list_emulations", return_value=catalogue):
            return related_emulations(_envelope(*chains))

    def test_atomic_links_on_one_shared_escalation_call(self, _detections):
        catalogue = [_emulation("backdoor_user", "atomic", ["iam:CreateAccessKey"])]
        chain = _chain("c1", ["iam:CreateUser(UserName=x)", "iam:AttachUserPolicy(UserName=x)", "iam:CreateAccessKey(UserName=x)"])
        links = self._related(catalogue, chain)["c1"]["emulations"]
        self.assertEqual([link["id"] for link in links], ["backdoor_user"])
        self.assertEqual(links[0]["tier"], "atomic")
        self.assertEqual(links[0]["sharedCalls"], ["iam:CreateAccessKey"])
        self.assertEqual(links[0]["detectionCount"], 2)

    def test_campaign_must_cover_every_call_of_a_short_path(self, _detections):
        catalogue = [
            _emulation("partial_campaign", "enterprise", ["iam:CreateUser"]),
            _emulation("full_campaign", "enterprise", ["iam:CreateUser", "iam:AttachUserPolicy"]),
        ]
        chain = _chain("c1", ["iam:CreateUser(UserName=x)", "iam:AttachUserPolicy(UserName=x)"])
        links = self._related(catalogue, chain)["c1"]["emulations"]
        self.assertEqual([link["id"] for link in links], ["full_campaign"])
        self.assertEqual(links[0]["tier"], "campaign")

    def test_campaign_never_links_on_a_single_shared_call(self, _detections):
        catalogue = [
            _emulation("campaign", "enterprise", ["iam:PassRole", "lambda:CreateFunction"]),
            _emulation("atomic", "atomic", ["iam:PassRole"]),
        ]
        chain = _chain("c1", ["iam:PassRole(RoleArn=arn:aws:iam::1:role/Deploy)"])
        links = self._related(catalogue, chain)["c1"]["emulations"]
        self.assertEqual([link["id"] for link in links], ["atomic"])

    def test_campaign_needs_three_calls_of_a_longer_path(self, _detections):
        chain = _chain("c1", [
            "iam:CreateUser(UserName=x)", "iam:AttachUserPolicy(UserName=x)", "iam:CreateAccessKey(UserName=x)",
            "iam:CreateLoginProfile(UserName=x)", "iam:AddUserToGroup(GroupName=g, UserName=x)",
        ])
        three = _emulation("three", "enterprise", ["iam:CreateUser", "iam:AttachUserPolicy", "iam:CreateAccessKey"])
        two = _emulation("two", "enterprise", ["iam:CreateUser", "iam:AttachUserPolicy"])
        links = self._related([three, two], chain)["c1"]["emulations"]
        self.assertEqual([link["id"] for link in links], ["three"])

    def test_a_shared_read_never_links(self, _detections):
        catalogue = [_emulation("reads_s3", "atomic", ["s3:GetObject", "s3:ListBucket"])]
        chain = _chain("c1", ["s3:PutBucketPolicy(Bucket=b)", "s3:GetObject(Bucket=b)"])
        self.assertEqual(self._related(catalogue, chain)["c1"]["emulations"], [])

    def test_assume_role_alone_never_links(self, _detections):
        catalogue = [_emulation("dns_logs", "atomic", ["sts:AssumeRole", "route53resolver:DeleteResolverQueryLogConfig"])]
        chain = _chain("c1", ["sts:AssumeRole(RoleArn=arn:aws:iam::1:role/admin)"])
        result = self._related(catalogue, chain)["c1"]
        self.assertEqual(result["escalationCalls"], [])
        self.assertEqual(result["emulations"], [])

    def test_ranks_by_calls_covered(self, _detections):
        catalogue = [
            _emulation("covers_one", "atomic", ["iam:CreateAccessKey"]),
            _emulation("covers_two", "atomic", ["iam:CreateUser", "iam:CreateAccessKey"]),
        ]
        chain = _chain("c1", ["iam:CreateUser(UserName=x)", "iam:CreateAccessKey(UserName=x)"])
        links = self._related(catalogue, chain)["c1"]["emulations"]
        self.assertEqual([link["id"] for link in links], ["covers_two", "covers_one"])

    def test_ignores_emulations_on_other_platforms(self, _detections):
        catalogue = [_emulation("k8s_thing", "atomic", ["iam:CreateAccessKey"], platform="k8s")]
        chain = _chain("c1", ["iam:CreateAccessKey(UserName=x)"])
        self.assertEqual(self._related(catalogue, chain)["c1"]["emulations"], [])

    def test_only_scans_with_findings_have_links(self, _detections):
        for envelope in (None, {"state": "clean", "chains": []}, {"state": "partial", "chains": []}):
            self.assertEqual(related_emulations(envelope), {})


@unittest.skipUnless(HAS_DRF, "DRF is not installed under config.settings.ci")
class DetailResponseTests(SimpleTestCase):
    """The scan detail response carries the links beside the stored result."""

    @mock.patch("apps.attack_graph.related.list_detection_summaries", return_value=[])
    @mock.patch(
        "apps.attack_graph.related.list_emulations",
        return_value=[_emulation("backdoor_user", "atomic", ["iam:CreateAccessKey"])],
    )
    def test_related_is_keyed_by_chain_id(self, _emulations, _detections):
        scan = ScoutScan(result=_envelope(_chain("c1", ["iam:CreateAccessKey(UserName=x)"])))
        data = ScoutScanDetailSerializer(scan).data
        self.assertEqual([link["id"] for link in data["related"]["c1"]["emulations"]], ["backdoor_user"])
        self.assertNotIn("related", data["result"]["chains"][0])
