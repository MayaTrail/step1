"""Tests for cost_estimator.estimate_cost.

Covers:
  - Known EC2 instance pricing (hardcoded table)
  - Windows premium applied correctly
  - Known service pricing (GuardDuty, CloudTrail, Secrets Manager, etc.)
  - Unrecognised resource types → $0, no crash
  - Transient resources from attack plan
  - EC2 price in-memory cache: same key → same result, no extra computation
  - Warning triggers (>$500/mo, GPU instances)
  - Return dict has all required keys
  - summary_table is a non-empty string
  - Empty infra plan → valid result with $0 totals
"""
import pytest
from cost_estimator import estimate_cost, _ec2_price_cache


def _infra(resources):
    return {"platform": "aws", "resources": resources}


def _resource(name, ptype, config_notes=""):
    return {"name": name, "pulumi_type": ptype, "configuration_notes": config_notes}


def _attack(steps=None):
    return {"attack_chain": steps or []}


class TestReturnShape:
    def test_all_top_level_keys_present(self):
        result = estimate_cost(_infra([]), _attack())
        for key in ("region", "platform", "standing_cost", "per_run_cost",
                    "cost_drivers", "warnings", "summary_table"):
            assert key in result, f"Missing key: {key}"

    def test_standing_cost_keys(self):
        result = estimate_cost(_infra([]), _attack())
        sc = result["standing_cost"]
        for key in ("hourly_usd", "daily_usd", "monthly_usd", "breakdown"):
            assert key in sc, f"Missing standing_cost key: {key}"

    def test_per_run_cost_keys(self):
        result = estimate_cost(_infra([]), _attack())
        pr = result["per_run_cost"]
        for key in ("estimated_usd", "detail", "breakdown"):
            assert key in pr, f"Missing per_run_cost key: {key}"

    def test_summary_table_is_nonempty_string(self):
        result = estimate_cost(_infra([_resource("vpc", "aws.ec2.Vpc")]), _attack())
        assert isinstance(result["summary_table"], str)
        assert len(result["summary_table"]) > 0


class TestEmptyPlan:
    def test_empty_infra_zero_cost(self):
        result = estimate_cost(_infra([]), _attack())
        assert result["standing_cost"]["hourly_usd"] == 0.0
        assert result["standing_cost"]["monthly_usd"] == 0.0

    def test_empty_infra_empty_breakdown(self):
        result = estimate_cost(_infra([]), _attack())
        assert result["standing_cost"]["breakdown"] == []

    def test_no_warnings_on_empty(self):
        result = estimate_cost(_infra([]), _attack())
        assert result["warnings"] == []


class TestEC2Pricing:
    def test_t2_micro_linux_known_price(self):
        r = _resource("web", "aws.ec2.Instance", "Instance type: t2.micro, Linux")
        result = estimate_cost(_infra([r]), _attack())
        hourly = result["standing_cost"]["hourly_usd"]
        assert abs(hourly - 0.0116) < 1e-6

    def test_t3_medium_linux(self):
        r = _resource("app", "aws.ec2.Instance", "Instance type: t3.medium")
        result = estimate_cost(_infra([r]), _attack())
        assert abs(result["standing_cost"]["hourly_usd"] - 0.0416) < 1e-6

    def test_windows_premium_applied(self):
        linux = _resource("lin", "aws.ec2.Instance", "Instance type: t2.micro")
        windows = _resource("win", "aws.ec2.Instance", "Instance type: t2.micro, Windows Server")
        r_linux = estimate_cost(_infra([linux]), _attack())["standing_cost"]["hourly_usd"]
        r_win   = estimate_cost(_infra([windows]), _attack())["standing_cost"]["hourly_usd"]
        # Windows should cost ~40% more
        assert r_win > r_linux
        assert abs(r_win / r_linux - 1.40) < 0.01

    def test_ec2_appears_in_breakdown(self):
        r = _resource("srv", "aws.ec2.Instance", "Instance type: t3.micro")
        result = estimate_cost(_infra([r]), _attack())
        bd = result["standing_cost"]["breakdown"]
        assert any("srv" in item["resource"] for item in bd)

    def test_gpu_instance_warning(self):
        r = _resource("gpu", "aws.ec2.Instance", "Instance type: p3.2xlarge")
        result = estimate_cost(_infra([r]), _attack())
        assert any("GPU" in w or "gpu" in w.lower() for w in result["warnings"])

    def test_high_cost_instance_warning(self):
        r = _resource("big", "aws.ec2.Instance", "Instance type: p4d.24xlarge")
        result = estimate_cost(_infra([r]), _attack())
        assert any("High-cost" in w or "high" in w.lower() for w in result["warnings"])


class TestServicePricing:
    def test_guardduty_known_price(self):
        r = _resource("gd", "aws.guardduty.Detector", "")
        result = estimate_cost(_infra([r]), _attack())
        assert abs(result["standing_cost"]["hourly_usd"] - 0.005) < 1e-6

    def test_cloudtrail_known_price(self):
        r = _resource("ct", "aws.cloudtrail.Trail", "")
        result = estimate_cost(_infra([r]), _attack())
        assert abs(result["standing_cost"]["hourly_usd"] - 0.0014) < 1e-6

    def test_secrets_manager_known_price(self):
        r = _resource("sec", "aws.secretsmanager.Secret", "")
        result = estimate_cost(_infra([r]), _attack())
        assert abs(result["standing_cost"]["hourly_usd"] - 0.00056) < 1e-6

    def test_zero_cost_resources_not_in_drivers(self):
        resources = [
            _resource("vpc",    "aws.ec2.Vpc", ""),
            _resource("subnet", "aws.ec2.Subnet", ""),
            _resource("iam",    "aws.iam.User", ""),
        ]
        result = estimate_cost(_infra(resources), _attack())
        assert result["standing_cost"]["hourly_usd"] == 0.0
        # cost_drivers only lists items with price > 0
        assert result["cost_drivers"] == []

    def test_multiple_resources_sum_correctly(self):
        resources = [
            _resource("gd", "aws.guardduty.Detector", ""),   # 0.005
            _resource("ct", "aws.cloudtrail.Trail", ""),      # 0.0014
        ]
        result = estimate_cost(_infra(resources), _attack())
        expected = 0.005 + 0.0014
        assert abs(result["standing_cost"]["hourly_usd"] - expected) < 1e-6


class TestUnrecognisedResources:
    def test_unknown_type_zero_cost_no_crash(self):
        r = _resource("mystery", "aws.something.Unknown", "")
        result = estimate_cost(_infra([r]), _attack())
        assert result["standing_cost"]["hourly_usd"] == 0.0

    def test_unknown_type_still_in_breakdown(self):
        r = _resource("mystery", "aws.something.Unknown", "")
        result = estimate_cost(_infra([r]), _attack())
        bd = result["standing_cost"]["breakdown"]
        assert any("mystery" in item["resource"] for item in bd)

    def test_unknown_type_shows_no_price_data_note(self):
        r = _resource("x", "azure.compute.VirtualMachine", "")
        result = estimate_cost(_infra([r]), _attack())
        bd = result["standing_cost"]["breakdown"]
        entry = next(item for item in bd if item["resource"] == "x")
        assert "unrecognised" in entry["detail"] or entry["hourly_usd"] == 0.0


class TestTransientResources:
    def test_transient_ec2_adds_per_run_cost(self):
        attack = {
            "attack_chain": [{
                "step": 5,
                "technique_id": "T1610",
                "transient_resources": [{
                    "type": "aws.ec2.Instance",
                    "instance_type": "t3.micro",
                    "os": "Linux",
                    "duration_minutes": 60,
                }]
            }]
        }
        result = estimate_cost(_infra([]), attack)
        # t3.micro Linux = 0.0104/hr × 1hr = 0.0104
        assert result["per_run_cost"]["estimated_usd"] > 0.0

    def test_no_transient_resources_zero_per_run(self):
        result = estimate_cost(_infra([]), _attack())
        assert result["per_run_cost"]["estimated_usd"] == 0.0

    def test_transient_detail_string_present(self):
        result = estimate_cost(_infra([]), _attack())
        assert "no transient" in result["per_run_cost"]["detail"].lower()


class TestHighCostWarning:
    def test_over_500_monthly_triggers_warning(self):
        # p4d.24xlarge = $32.77/hr → >$500/mo
        r = _resource("hpc", "aws.ec2.Instance", "Instance type: p4d.24xlarge")
        result = estimate_cost(_infra([r]), _attack())
        assert any("500" in w for w in result["warnings"])

    def test_under_500_monthly_no_cost_warning(self):
        r = _resource("cheap", "aws.ec2.Instance", "Instance type: t2.micro")
        result = estimate_cost(_infra([r]), _attack())
        cost_warnings = [w for w in result["warnings"] if "500" in w]
        assert cost_warnings == []


class TestEC2PriceCache:
    def test_cache_populated_after_call(self):
        _ec2_price_cache.clear()
        r = _resource("inst", "aws.ec2.Instance", "Instance type: t2.micro")
        estimate_cost(_infra([r]), _attack())
        # At least one entry should now be in the cache
        assert len(_ec2_price_cache) > 0

    def test_same_type_returns_identical_price(self):
        r = _resource("a", "aws.ec2.Instance", "Instance type: t3.small")
        result1 = estimate_cost(_infra([r]), _attack())["standing_cost"]["hourly_usd"]
        result2 = estimate_cost(_infra([r]), _attack())["standing_cost"]["hourly_usd"]
        assert result1 == result2

    def test_linux_and_windows_cached_separately(self):
        _ec2_price_cache.clear()
        rl = _resource("l", "aws.ec2.Instance", "Instance type: t3.micro, Linux")
        rw = _resource("w", "aws.ec2.Instance", "Instance type: t3.micro, Windows")
        estimate_cost(_infra([rl, rw]), _attack())
        # Should have two distinct cache entries (one per OS)
        assert len(_ec2_price_cache) >= 2


class TestDailyAndMonthlyDerivation:
    def test_daily_is_24x_hourly(self):
        r = _resource("gd", "aws.guardduty.Detector", "")
        result = estimate_cost(_infra([r]), _attack())
        sc = result["standing_cost"]
        assert abs(sc["daily_usd"] - sc["hourly_usd"] * 24) < 1e-4

    def test_monthly_is_30x_daily(self):
        r = _resource("gd", "aws.guardduty.Detector", "")
        result = estimate_cost(_infra([r]), _attack())
        sc = result["standing_cost"]
        assert abs(sc["monthly_usd"] - sc["daily_usd"] * 30) < 0.01
