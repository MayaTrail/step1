# Detection Note — T1685.002 (WAF Logging Stopped)

**Signal:** a web ACL stops writing request records — by configuration deletion, by a DROP
filter, or by the delivery permission being removed underneath it.

**The detection depends on the telemetry the technique disables.** That is the whole
problem, and it is why the deployable rules here watch **CloudTrail**, not the WAF stream.
An absence alert's input is precisely what the attacker removed.

## Why the source rule cannot be the control

It fires when no WAF records arrive in a window. Four things produce that, and only one is
an incident:

1. `DeleteLoggingConfiguration` — the incident.
2. A `LoggingFilter` with `DefaultBehavior: DROP` and no keeping filter — the incident, and
   **`GetLoggingConfiguration` still returns a configuration and the console still shows
   logging as enabled.**
3. The delivery permission removed — the log-group resource policy, the S3 bucket policy,
   or the Firehose service-linked role. **WAF's own configuration is untouched and correct.**
4. **Genuinely no traffic** — a dev endpoint overnight, a decommissioned ACL, a DNS cutover.

The alert reports all four identically, and the fourth is common. So it is retained as a
corroborating signal and replaced, as the control, by three rules on the control-plane calls
that produce silence — all of which are CloudTrail management events that survive the WAF
stream stopping.

## The two ways logging stops without a delete

**`PutLoggingConfiguration` completely replaces the previous configuration.** AWS: *"This
operation completely replaces any mutable specifications that you already have for a logging
configuration with the ones that you provide to this call."* It is therefore both the enable
call and the silence call, which is why the rule on it is deliberately broad at `medium` and
the resulting configuration decides the disposition.

A `LoggingFilter` has `DefaultBehavior` of `KEEP | DROP`, and each filter has `Behavior`,
a `Requirement` of `MEETS_ALL | MEETS_ANY`, and conditions on action or label.
`ActionCondition.Action` accepts `ALLOW | BLOCK | COUNT | CAPTCHA | CHALLENGE | MONETIZE |
EXCLUDED_AS_COUNT`. **`DefaultBehavior: DROP` with an empty `Filters` array discards
everything**, and nothing in the console or in `GetLoggingConfiguration` reads as disabled.

**`RedactedFields` blanks named components.** Redacted fields appear in the record as the
literal string `xxx` — not as absent keys — so a query looking for missing fields will not
find them. Redaction has no effect on request sampling or on Security Lake.

Neither is a WAF *rule* change, so neither appears in a web-ACL diff.

## The ordering hazard in the response

**Fixing logging destroys the evidence of how it was broken.** The only way to restore it is
`PutLoggingConfiguration`, and that call is a full replacement — so it overwrites the DROP
filter or the redaction you would want to have captured. Read and save the current
configuration **before** repairing it. That is why §3 Step 1 captures and §3 Step 2 repairs,
and not the other way round.

## What survives, and the clock on it

For any window in which the web ACL had no logging configuration, **there is no per-request
record and there never will be.** Nothing reconstructs it. Three weaker sources survive:

| Source | What it gives | Limit |
|---|---|---|
| CloudWatch `AWS/WAFV2` metrics | counts by action, 1-minute resolution | **no request content**; governed by `VisibilityConfig.CloudWatchMetricsEnabled`, which is independent of logging |
| `GetSampledRequests` | a random sample from the first 5,000 requests in a chosen window, `MaxItems` 1–500, with `Labels`, `Action`, `ClientIP`, `Country`, `Headers`, `Method`, `URI` | **previous three hours only**, and it has **no query string and no body** |
| Amazon Security Lake | full records, if configured | configured in Security Lake, not in WAF; the redacted-fields setting has no effect on it |

**The three-hour sampling window is the only thing that expires**, so it is the first thing
to capture and the reason evidence collection precedes remediation.

## Constraints worth knowing before you repair anything

- The destination name **must begin with `aws-waf-logs-`**. A log group called `waf-logs-prod`
  cannot be selected — a repair that fails for this reason looks like a permissions problem.
- **One logging destination per web ACL.** There is no fan-out and no second copy, so there
  is no redundant stream to fall back on.
- The destination must be in the **same Region and account** as the web ACL.
- Enabling logging causes AWS to create a resource policy (CloudWatch Logs), a bucket policy
  (S3), or a service-linked role (Firehose). Those are the permissions cause 3 removes.

## Response levers

**MITRE:** The
live mapping is **T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log**, tactic
**Defense Impairment (TA0112)**; TA0005 was renamed *Stealth*.

**GuardDuty:** no finding type covers AWS WAF. GuardDuty has no WAF resource type at all, so nothing here is duplicated by it — these rules are the only coverage for this technique.

**Files here:**
- `sigma_t1685_002.yml` — three documents: configuration deleted (`high`), configuration
  replaced (`medium`, deliberately broad because the content decides), and delivery
  permission removed (`medium`).
- `kql_t1685_002.kql` — the control-plane view, with the verdict distinguishing a delete
  from a DROP filter from a redaction.

Full response procedure is in `../PLAYBOOK.md`.
