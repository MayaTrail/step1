"""
The scan result contract.

Two things are being defended here. The first is the boundary: Scout is
maintained in its own repository, and if its chain objects reach the frontend
unchanged then a Scout upgrade is a frontend outage. The second is the reason
this product exists — a scan that could not read the account must never render
as an account with nothing to find. That rule is one branch in result_state(),
and these tests are what keep it there.

Field names below follow Scout's real output, verified in Task 1 against the
pinned commit (see docs/superpowers/specs/2026-09-21-attack-graph-integration-design.md,
"Assumptions to verify" and the envelope field-mapping table) — not the
pre-verification guess. Notably: chains carry `hops`, not `steps`; hops carry
no per-hop `technique` or `condition`; `mitre_techniques` is chain-level.
"""

import json
import pathlib
from datetime import datetime, timezone

from django.test import SimpleTestCase

from apps.attack_graph.envelope import (
    EVALUATOR,
    MAX_CHAINS,
    SCHEMA_VERSION,
    result_state,
    serialize_scan,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SCANNED_AT = datetime(2026, 9, 21, 10, 4, tzinfo=timezone.utc)


def _envelope(report, mode="account"):
    return serialize_scan(
        report=report,
        collection={"mode": mode},
        account_id="123456789012",
        scanned_at=SCANNED_AT,
    )


class SerializeScanTests(SimpleTestCase):
    """What the envelope carries."""

    def setUp(self):
        self.report = json.loads((FIXTURES / "scout_report.json").read_text("utf-8"))

    def test_it_stamps_the_schema_version(self):
        self.assertEqual(_envelope(self.report)["schema_version"], SCHEMA_VERSION)

    def test_it_records_the_collection_mode_and_account(self):
        envelope = _envelope(self.report)
        self.assertEqual(envelope["mode"], "account")
        self.assertEqual(envelope["account_id"], "123456789012")
        self.assertEqual(envelope["scanned_at"], "2026-09-21T10:04:00+00:00")

    def test_it_records_that_scps_were_not_applied(self):
        self.assertEqual(_envelope(self.report)["evaluator"], EVALUATOR)

    def test_every_chain_carries_a_rank_and_its_endpoints(self):
        chain = _envelope(self.report)["chains"][0]
        self.assertEqual(chain["rank"], 1)
        for end in ("source", "target"):
            self.assertIn("id", chain[end])
            self.assertIn("label", chain[end])
        step = chain["steps"][0]
        # No "technique" or "condition" here on purpose: Scout does not
        # attach either per hop (verified in Task 1). A per-step technique
        # would be a chain-level mitre_techniques entry duplicated onto every
        # hop — a false claim about which technique applies where.
        for key in ("from", "to", "mechanism", "action"):
            self.assertIn(key, step)

    def test_mitre_techniques_are_carried_on_the_chain_not_the_step(self):
        # Scout attaches MITRE technique ids to the chain as a whole, not to
        # individual hops. The envelope must surface that list once, on the
        # chain, rather than inventing a per-step value.
        chains = _envelope(self.report)["chains"]
        self.assertEqual(chains[0]["mitre_techniques"], ["T1098.003"])
        self.assertEqual(chains[1]["mitre_techniques"], ["T1528", "T1098.003"])

    def test_an_unknown_mode_fails_safe_to_partial(self):
        # A Scout upgrade that renames or drops the mode key must fail safe.
        # Defaulting the other way turns an unreadable account into a clean one.
        envelope = serialize_scan(
            report=self.report, collection={}, account_id="1", scanned_at=SCANNED_AT,
        )
        self.assertEqual(envelope["state"], "partial")

    def test_an_unknown_mode_is_not_relabelled_as_self(self):
        # "self" is a specific claim: Scout enumerated only the role it
        # assumed, which the UI explains as "the audit role's policy no
        # longer grants iam:GetAccountAuthorizationDetails, reconnect it".
        # Writing that word in when Scout reported no mode at all would have
        # the product assert a cause it never observed — the same error as a
        # false all-clear, one level up. Fail safe on the state; stay honest
        # about the reason.
        envelope = serialize_scan(
            report=self.report, collection={}, account_id="1", scanned_at=SCANNED_AT,
        )
        self.assertEqual(envelope["mode"], "unknown")

    def test_a_reported_mode_is_carried_through_verbatim(self):
        envelope = serialize_scan(
            report=self.report,
            collection={"mode": "self"},
            account_id="1",
            scanned_at=SCANNED_AT,
        )
        self.assertEqual(envelope["mode"], "self")

    def test_a_chains_source_and_target_are_its_first_and_last_hop(self):
        # A chain is a path from its origin to its terminal target. Scout
        # expresses both only as ARNs — there is no separate node-id space
        # (verified in Task 1: every hop endpoint ARN in the sample fixture
        # also appears as some chain's origin or terminal ARN) — so the
        # envelope keys source/target.id on the same ARN the first/last hop
        # names. That is the property the graph relies on to draw one
        # connected path per chain instead of disconnected fragments.
        for chain in _envelope(self.report)["chains"]:
            if not chain["steps"]:
                continue
            self.assertEqual(chain["steps"][0]["from"], chain["source"]["id"], chain["id"])
            self.assertEqual(chain["steps"][-1]["to"], chain["target"]["id"], chain["id"])

    def test_consecutive_steps_join_up(self):
        # The same property within a chain: step N's target is step N+1's
        # source, or the chain is not a chain.
        for chain in _envelope(self.report)["chains"]:
            for earlier, later in zip(chain["steps"], chain["steps"][1:]):
                self.assertEqual(earlier["to"], later["from"], chain["id"])

    def test_it_truncates_and_says_so(self):
        many = {"chains": self.report["chains"] * 40}
        envelope = _envelope(many)
        self.assertEqual(len(envelope["chains"]), MAX_CHAINS)
        self.assertTrue(envelope["truncated"])

    def test_an_untruncated_result_says_that_too(self):
        self.assertFalse(_envelope(self.report)["truncated"])

    def test_no_scout_object_survives_serialization(self):
        # The envelope must be plain JSON: anything else means a Scout type
        # leaked through and the frontend is now coupled to it.
        json.dumps(_envelope(self.report))

    def test_terminal_impact_is_carried_through_for_zero_hop_chains(self):
        # Scout reports a chain with zero hops when an identity already holds
        # the impact directly. Without this field the frontend cannot tell
        # that case apart from "nothing to say about this node" — both would
        # render as an isolated box with a score and no explanation.
        chain = _envelope(self.report)["chains"][0]
        self.assertEqual(chain["terminal_impact"], "FULL_ACCOUNT_COMPROMISE")

    def test_a_missing_terminal_impact_is_none_not_a_crash(self):
        report = {"chains": [{**self.report["chains"][0], "terminal_impact": None}]}
        chain = _envelope(report)["chains"][0]
        self.assertIsNone(chain["terminal_impact"])

    def test_chain_ids_are_serializer_assigned_not_scouts_own(self):
        # Scout's own chain_id (e.g. "CHN-7540184B") is opaque and not
        # guaranteed stable across scans, so it must never surface. A
        # serializer that only falls back to "chain-{rank}" when Scout's id
        # is absent would silently start leaking it the day Scout adds one.
        chain = _envelope(self.report)["chains"][0]
        self.assertEqual(chain["id"], "chain-1")
        self.assertNotEqual(chain["id"], self.report["chains"][0]["chain_id"])


class ResultStateTests(SimpleTestCase):
    """The one rule this product cannot get wrong."""

    def test_a_full_scan_with_chains_reports_findings(self):
        envelope = {"mode": "account", "chains": [{"id": "chain-1"}]}
        self.assertEqual(result_state(envelope), "findings")

    def test_a_full_scan_with_no_chains_is_clean(self):
        self.assertEqual(result_state({"mode": "account", "chains": []}), "clean")

    def test_a_self_scoped_scan_with_no_chains_is_partial_never_clean(self):
        # Scout falls back to enumerating only the assumed role when it cannot
        # read account-wide IAM. That yields zero chains. Reporting it as clean
        # tells a customer their account has no privilege-escalation paths on
        # the strength of a scan that never looked.
        state = result_state({"mode": "self", "chains": []})
        self.assertEqual(state, "partial")
        self.assertNotEqual(state, "clean")

    def test_a_self_scoped_scan_with_chains_is_still_partial(self):
        self.assertEqual(result_state({"mode": "self", "chains": [{"id": "c"}]}), "partial")

    def test_any_mode_that_is_not_account_is_partial(self):
        # The rule is a whitelist, not a blacklist of "self". A mode Scout
        # invents in a future release must land on the cautious side without
        # this module being edited.
        for mode in ("self", "unknown", "partial-org", ""):
            self.assertEqual(result_state({"mode": mode, "chains": []}), "partial", mode)

    def test_the_state_is_stamped_into_the_envelope(self):
        # The frontend reads envelope["state"] rather than re-deriving the rule
        # in TypeScript, so there is exactly one implementation of it.
        envelope = serialize_scan(
            report={"chains": []},
            collection={"mode": "self"},
            account_id="1",
            scanned_at=SCANNED_AT,
        )
        self.assertEqual(envelope["state"], "partial")
