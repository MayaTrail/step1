# Ground truth — AWS WAF (web ACL traffic logs)

Audited once, on 2026-08-29, against the AWS WAF Developer Guide and the WAFv2 API Reference.
Every `waf.*` playbook is written from this file. Where a claim could not be verified it says so
here rather than being softened in a playbook.

Pages used: `logging.html`, `logging-management-configure.html`, `logging-destinations.html`,
`logging-cw-logs.html`, `logging-fields.html`, `logging-examples.html`,
`waf-oversize-request-components.html`, `aws-managed-rule-groups-baseline.html`,
`aws-managed-rule-groups-use-case.html`, `aws-managed-rule-groups-ip-rep.html`,
`waf-metrics.html`, `logging-using-cloudtrail.html`, and the API pages
`API_PutLoggingConfiguration`, `API_LoggingFilter`, `API_ActionCondition`,
`API_GetSampledRequests`.

---

## 1. WAF traffic logs are not CloudTrail, and they are off by default

Two separate, unrelated streams exist and are constantly confused:

| | Web ACL traffic log | CloudTrail |
|---|---|---|
| What it holds | one record per **web request** WAF evaluated | one record per **WAF API call** |
| Where it goes | CloudWatch Logs log group, S3 bucket, or Firehose delivery stream | the account's trail |
| On by default | **No** | management events yes |
| Field shape | `httpRequest`, `labels`, `action`, `terminatingRuleId` … | `eventSource`, `userIdentity`, `requestParameters` … |

**Logging is enabled per web ACL by `wafv2:PutLoggingConfiguration` and by nothing else.** A web
ACL that has never had that call made against it evaluates traffic, blocks it, and writes no
request records anywhere. There is no account-level default and no organisation-level default.

Constraints that are load-bearing for a responder, all verified:

- **The destination name must start with `aws-waf-logs-`.** True for all three destination types.
  A log group called `waf-logs-prod` cannot be selected. Log group ARN form:
  `arn:aws:logs:<Region>:<account-id>:log-group:aws-waf-logs-<suffix>`; log streams are named
  `<Region>_<web-acl-name>_<n>`, e.g. `us-east-1_TestWebACL_0`.
- **One logging destination per web ACL.** AWS states it outright: *"You can define one logging
  destination per web ACL."* There is no fan-out and no second copy.
- The log group must be in the **same Region and same account** as the web ACL.
- `PutLoggingConfiguration` **completely replaces** the existing configuration: *"This operation
  completely replaces any mutable specifications that you already have for a logging configuration
  with the ones that you provide to this call."* This is the ordering trap in §5 of
  `waf.stealth.no-logs-from-aws-waf` — calling it to "fix" logging destroys the record of what the
  configuration was.
- Enabling logging causes AWS to create a **resource policy** on the log group (CloudWatch Logs
  destination), a **bucket policy** (S3), or a **service-linked role** (Firehose). Removing that
  policy out from under a live configuration breaks delivery without touching the WAF config.
- The permissions to change it are `wafv2:PutLoggingConfiguration` and
  `wafv2:DeleteLoggingConfiguration`, plus `logs:CreateLogDelivery` / `logs:DeleteLogDelivery` /
  `logs:PutResourcePolicy` for the CloudWatch Logs path.

### What is unavailable if logging was never enabled

Say this plainly rather than implying coverage: **for any window in which the web ACL had no
logging configuration, there is no per-request record and there never will be.** Nothing
reconstructs it. Three things survive, and all three are strictly weaker:

1. **CloudWatch metrics** (`AWS/WAFV2`) — counts only, no request content, one-minute resolution.
   They prove that traffic existed and how it was actioned. They are governed by each rule's and
   the web ACL's `VisibilityConfig.CloudWatchMetricsEnabled`, which is independent of logging.
2. **`GetSampledRequests`** — *"a sample that AWS WAF randomly selects from among the first 5,000
   requests that your AWS resource received during a time range that you choose … you can specify
   any time range in the previous three hours"*, `MaxItems` 1–500. It carries `Labels`, `Action`,
   `RuleNameWithinRuleGroup`, `ResponseCodeSent`, and a `Request` object of `ClientIP`, `Country`,
   `Headers`, `HTTPVersion`, `Method`, `URI`. **It has no query-string field and no body**, so it
   is not a substitute for the log even inside its window. Governed by
   `VisibilityConfig.SampledRequestsEnabled`.
3. **Amazon Security Lake**, if separately configured. Configured entirely in Security Lake, not
   in the WAF logging configuration; the WAF redacted-fields setting has no effect on it.

The three-hour sampling window is the only thing that expires, which is why evidence capture comes
before remediation in the no-logs playbook.

### Two ways logs stop without `DeleteLoggingConfiguration`

- **`LoggingFilter`** on the logging configuration drops records before delivery.
  `DefaultBehavior` is `KEEP | DROP`; each `Filter` has `Behavior` (`KEEP | DROP`), a
  `Requirement` (`MEETS_ALL | MEETS_ANY`) and `Conditions` of `ActionCondition` or
  `LabelNameCondition`. `ActionCondition.Action` valid values:
  `ALLOW | BLOCK | COUNT | CAPTCHA | CHALLENGE | MONETIZE | EXCLUDED_AS_COUNT`. A filter of
  `DefaultBehavior: DROP` with no keeping filter silences the stream while
  `GetLoggingConfiguration` still returns a configuration and the console still shows logging as
  enabled.
- **`RedactedFields`** blanks named components in the record. **Redacted fields appear in the logs
  as `xxx`** — not as absent keys. Redaction has no effect on request sampling or Security Lake.

Neither is a WAF rule change, so neither shows up in a web-ACL diff.

---

## 2. The log record — exact fields and nesting

Verified against `logging-fields.html` and the JSON examples in `logging-examples.html`.

Top level, flat: `timestamp` (ms), `formatVersion`, `webaclId` (the web ACL **ARN**, despite the
name), `terminatingRuleId`, `terminatingRuleType`, `action`, `terminatingRuleMatchDetails`,
`httpSourceName`, `httpSourceId`, `ruleGroupList`, `rateBasedRuleList`,
`nonTerminatingMatchingRules`, `requestHeadersInserted`, `responseCodeSent`, `httpRequest`,
`labels`, `captchaResponse`, `challengeResponse`, `oversizeFields`, `ja3Fingerprint`,
`ja4Fingerprint`, `clientAsn`, `forwardedAsn`, `fragment`.

Nesting that a flat path silently misses:

- **`labels` is an array of single-key objects: `[{"name": "<label>"}]`.** Not an array of
  strings. The path is `labels[].name`. AWS logs **the first 100 labels** on a request.
- **`httpRequest` is a nested object**: `.clientIp`, `.country` (`-` when undetermined), `.uri`,
  `.args` (the query string), `.httpVersion`, `.httpMethod`, `.requestId`, and `.headers` which is
  itself an array of `{"name":…, "value":…}`. **There is no `httpRequest.host`** — the Host value
  lives inside the `headers` array and has to be picked out of it.
- **`ruleGroupList[]`** carries `.ruleGroupId`, `.terminatingRule` (an object of `ruleId`,
  `action`, `ruleMatchDetails`), `.nonTerminatingMatchingRules[]` (each `ruleId`, `action`,
  `ruleMatchDetails`, and `captchaResponse`/`challengeResponse` where applicable) and
  `.excludedRules` (each `exclusionType`, `ruleId`). `excludedRules` is `null` when there are none.
- **`terminatingRuleMatchDetails` and `ruleMatchDetails` are populated only for SQL-injection and
  cross-site-scripting match statements.** AWS: *"This field is only populated for SQL injection
  and cross-site scripting (XSS) match rule statements."* Their sub-keys are `conditionType`
  (`SQL_INJECTION`, `XSS`), `sensitivityLevel` (`LOW`, `HIGH` — SQLi only), `location`
  (`HEADER`, `URI`, `QUERY_STRING`, `BODY`, and **`UNKNOWN` for JSON body inspection**, which AWS
  documents explicitly), and `matchedData`, an **array of tokens**, not a string.
  Consequence: **a regex/byte-match rule such as `Log4JRCE_*` or `EC2MetaDataSSRF_*` produces no
  `matchedData` at all.** Any triage flow that expects the matched payload for those rules gets
  an empty array, and the payload has to come from `httpRequest.uri` / `.args` / `.headers`.
  Also recorded by AWS: the CRS `CrossSiteScripting_*` rules do not populate match details in
  version 2.0 of that rule group.
- `oversizeFields` is a list of zero or more of `REQUEST_BODY`, `REQUEST_JSON_BODY`,
  `REQUEST_HEADERS`, `REQUEST_COOKIES` — *"If a field is oversize but the web ACL doesn't inspect
  it, it won't be listed here."*
- `httpSourceName` values: `CF`, `APIGW`, `ALB`, `APPSYNC`, `COGNITOIDP`, `APPRUNNER`,
  `VERIFIED_ACCESS`. This is how you tell which body size limit applied — see §5.
- `requestId` is the ALB **trace ID** for ALB and the request ID for everything else.

**The body is never in the log.** WAF logs headers and the query string, and does not log the
request body. For any body-inspection finding, the payload has to come from the application.

---

## 3. The terminating action is the discriminator, not a filter

`action` carries the **terminating** action, uppercase in the record: `ALLOW`, `BLOCK`, `CAPTCHA`,
`CHALLENGE` (and `MONETIZE` where that action is in use). When nothing terminated the request,
`terminatingRuleId` is the literal string **`Default_Action`** and `action` is the web ACL's
default action.

**CAPTCHA and Challenge are terminating actions.** AWS: *"The CAPTCHA and Challenge actions are
terminating when the web request doesn't contain a valid token."* Verified in the log examples: a
CAPTCHA rule matching a request with **no** token yields `"action":"CAPTCHA"` with
`responseCodeSent: 405` and `captchaResponse.failureReason: "TOKEN_MISSING"`; the same rule
matching a request **with** a valid token yields `"action":"ALLOW"` at the top level, with the
CAPTCHA match recorded under `nonTerminatingMatchingRules[].action = "CAPTCHA"`.

So, for the question every one of these playbooks has to answer — *did the request reach the
application?*:

| `action` | Reached the application | Verdict weight |
|---|---|---|
| `ALLOW` | **Yes** | highest — the payload was served to the backend |
| `CAPTCHA` / `CHALLENGE` (top-level) | **No** — WAF answered with an interstitial | low; an attempt, stopped |
| `BLOCK` | No | low as a single event; high as a volume signal |
| `ALLOW` with a rule under `nonTerminatingMatchingRules` | **Yes** | the Count/valid-token case — treat as reached |

**Every source rule in this WAF set gates on `action:"ALLOW"`, and every managed rule they match
on has a default action of Block.** The consequence, verified rule by rule in §6: in a web ACL
running the managed rule groups at their defaults, these alerts do not fire, and a blocked attempt
raises nothing at all — the attacker is invisible exactly when the control is working. The
correction is the same in every playbook: **make the terminating action a verdict axis, never a
filter.** The deployable Sigma matches the label and emits the action as a field; `ALLOW` is P0/P1,
`BLOCK`/`CAPTCHA`/`CHALLENGE` is P2/P3 on volume.

The four configurations in which an `ALLOW` can coexist with a managed-rule label — worth knowing
because they are the finding, not the noise:

1. The rule group is **overridden to Count** (`OverrideAction: Count` on the rule group, or a
   `RuleActionOverride` to Count on the specific rule). The label is still added; the request is
   still allowed.
2. The specific rule is **excluded** — logged in `ruleGroupList[].excludedRules` and matched by
   the `EXCLUDED_AS_COUNT` action condition.
3. An **earlier Allow rule terminated** evaluation before the managed group ran — but then the
   managed group never ran, so no label is added and the alert cannot fire either way.
4. The rule matched **non-terminatingly** (Count action inside the group, or a CAPTCHA/Challenge
   rule against a valid token), so evaluation continued and something later allowed the request.

Cases 1 and 2 are the realistic ones, and both mean the same thing: **the protection is off for
that rule.** That is the alert's actual meaning, and it is not what its title says.

---

## 4. Labels — exact strings, case-sensitive, and there is no transform

A label is `awswaf:managed:aws:<rule-group-slug>:<RuleLabelName>`. The label is applied whenever
the rule **matches**, regardless of the action taken, and labels are available to rules that run
**after** the labelling rule in the same web ACL evaluation. Label matching is case-sensitive.

**The managed rule *name* and the label it emits are not related by any mechanical transform.**
This is not a rule of thumb; it is a set of individually-documented strings. Counter-examples that
break every transform anyone would write:

| Rule name | Emitted label tail | Breaks |
|---|---|---|
| `EC2MetaDataSSRF_URIPATH` | `EC2MetaDataSSRF_URIPath` | title-case → `Uripath` |
| `EC2MetaDataSSRF_QUERYARGUMENTS` | `EC2MetaDataSSRF_QueryArguments` | title-case → `Queryarguments` |
| `SQLi_URIPATH` | `SQLi_URIPath` | — |
| `SQLiExtendedPatterns_URIPATH` | `SQLiExtendedPatterns_UriPath` | **`UriPath`, in the same rule group as `SQLi_URIPath`** |
| `WindowsShellCommands_URIPATH` | `WindowsShellCommands_UriPath` | same split again |
| `PHPHighRiskMethodsVariables_URIPATH` | `PHPHighRiskMethodsVariables_URIPath` | and back again |
| `Host_localhost_HEADER` | `Host_Localhost_Header` | the lowercase `localhost` is capitalised |
| `UserAgent_BadBots_HEADER` | `BadBots_Header` | **the label drops a whole name segment** |
| `WordPressExploitableCommands_QUERYSTRING` | `WordPressExploitableCommands_QUERYSTRING` | label stays screaming-case |

So: **read every label off the managed-rule-group documentation, one at a time.** A rule that
title-cases `_URIPATH` returns zero forever against `SQLiExtendedPatterns_UriPath` and also zero
against `EC2MetaDataSSRF_URIPath`, in opposite directions. A rule that matches the WordPress group
with camel-case returns zero. Anchoring a match on the substring `_URIPath` misses `_UriPath` and
vice versa; matching the component-independent stem (`EC2MetaDataSSRF_`, `SQLi_`) and reading the
component off the matched label is the shape that survives.

The four SSRF labels, exactly:

```
awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_Body
awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_Cookie
awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_QueryArguments
awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_URIPath
```

---

## 5. Size limits — a real evasion path, and only for the body rules

| Component | Limit | Adjustable |
|---|---|---|
| **Body / JSON body**, ALB and AppSync | **8 KB, fixed** | **No** |
| **Body / JSON body**, CloudFront, API Gateway, Cognito, App Runner, Verified Access, Bedrock AgentCore Gateway | **16 KB default** | Yes, to **64 KB**, in the web ACL's `AssociationConfig` |
| Headers | first **8 KB (8,192 bytes)** or first **200 headers**, whichever comes first | No |
| Cookies | first **8 KB (8,192 bytes)** or first **200 cookies**, whichever comes first | No |

Oversize handling per rule statement: **`Continue`** (inspect what fits), **`Match`** (treat as
matching without inspecting), **`No match`** (treat as not matching without inspecting). *"In the
AWS WAF console, you're required to choose one of these handling options. Outside the console, the
default option is Continue."*

**Every AWS managed body rule uses `Continue`** — verified individually for `EC2MetaDataSSRF_BODY`,
`SQLi_BODY`, `SQLiExtendedPatterns_BODY`, `Log4JRCE_BODY`, `GenericLFI_BODY`, `GenericRFI_BODY`,
`CrossSiteScripting_BODY`, `JavaDeserializationRCE_BODY`, `ReactJSRCE_BODY`,
`PHPHighRiskMethodsVariables_BODY`, `WindowsShellCommands_BODY`, `PowerShellCommands_BODY`,
`UNIXShellCommandsVariables_BODY`.

`Continue` plus a fixed limit is an evasion path, stated precisely: **anything past the limit is
not inspected, and the whole body is still forwarded to the application.** AWS says so —
*"When AWS WAF allows a web request to proceed to your protected resource, the entire web request
is sent, including any contents that are outside of the count and size limits that AWS WAF was
able to inspect."* Padding a request with 8 KB of filler in front of the payload defeats every
body rule on an ALB-fronted application, and the log shows it: `oversizeFields` contains
`REQUEST_BODY` or `REQUEST_JSON_BODY` while no body rule matched.

**Scope this caveat to body rules only.** `EC2MetaDataSSRF_URIPath`, `_QueryArguments` and
`_Cookie`, and `Log4JRCE_URIPath` / `_QueryString`, do not inspect the body and are not affected
by the body limit. The CRS also ships `SizeRestrictions_BODY` (Block, over 8,192 bytes) which, when
present and not overridden, blocks the padding trick outright — its presence in the web ACL is
therefore a compensating control worth checking before writing off the body rules.

---

## 6. The managed rule groups these use cases depend on

Every rule below is **Rule action: Block** unless marked otherwise. Verified 2026-08-29.

**Core rule set — `AWSManagedRulesCommonRuleSet`, WCU 700, label namespace `core-rule-set`.**
`EC2MetaDataSSRF_BODY` → `EC2MetaDataSSRF_Body`, `EC2MetaDataSSRF_COOKIE` → `EC2MetaDataSSRF_Cookie`,
`EC2MetaDataSSRF_URIPATH` → `EC2MetaDataSSRF_URIPath`, `EC2MetaDataSSRF_QUERYARGUMENTS` →
`EC2MetaDataSSRF_QueryArguments`. Also `SizeRestrictions_BODY` (over 8,192 bytes),
`SizeRestrictions_QUERYSTRING` (2,048), `SizeRestrictions_URIPATH` (1,024),
`SizeRestrictions_Cookie_HEADER` (10,240), the `GenericLFI_*`, `GenericRFI_*`,
`RestrictedExtensions_*` and `CrossSiteScripting_*` families, `NoUserAgent_HEADER` and
`UserAgent_BadBots_HEADER`. **The CRS contains no SQLi rule** — SQLi lives in the SQL database
group below, which is not part of a baseline deployment.

**Known bad inputs — `AWSManagedRulesKnownBadInputsRuleSet`, WCU 200, namespace `known-bad-inputs`.**
Log4j (CVE-2021-44228, CVE-2021-45046, CVE-2021-45105): `Log4JRCE_HEADER` → `Log4JRCE_Header`,
`Log4JRCE_QUERYSTRING` → `Log4JRCE_QueryString`, `Log4JRCE_BODY` → `Log4JRCE_Body`,
`Log4JRCE_URIPATH` → `Log4JRCE_URIPath`. Also `JavaDeserializationRCE_{HEADER,BODY,URIPATH,QUERYSTRING}`
→ `_Header`, `_Body`, `_URIPath`, `_QueryString`; `Host_localhost_HEADER` → `Host_Localhost_Header`;
`PROPFIND_METHOD` → `Propfind_Method`; `ExploitablePaths_URIPATH` → `ExploitablePaths_URIPath`;
`ReactJSRCE_BODY` → `ReactJSRCE_Body` (CVE-2025-55182). **There is no `Log4JRCE_COOKIE`** — cookies
are covered only insofar as the Cookie header falls under `Log4JRCE_Header`, subject to the 8 KB
header limit.

**SQL database — `AWSManagedRulesSQLiRuleSet`, WCU 200, namespace `sql-database`.**
`SQLi_QUERYARGUMENTS` → `SQLi_QueryArguments`, `SQLiExtendedPatterns_QUERYARGUMENTS` →
`SQLiExtendedPatterns_QueryArguments`, `SQLi_BODY` → `SQLi_Body`, `SQLiExtendedPatterns_BODY` →
`SQLiExtendedPatterns_Body`, `SQLiExtendedPatterns_HEADER` → `SQLiExtendedPatterns_Header`,
`SQLiExtendedPatterns_URIPATH` → `SQLiExtendedPatterns_UriPath`, `SQLi_COOKIE` → `SQLi_Cookie`,
`SQLi_URIPATH` → `SQLi_URIPath`. The `SQLi_*` rules use the built-in SQL-injection match statement
at **sensitivity Low**; the `SQLiExtendedPatterns_*` rules cover patterns the `SQLi_*` rules do not.
This group is **use-case specific and not part of a baseline deployment** — if it is absent, every
SQLi label is absent and the corresponding alert is silent for a configuration reason, not a
traffic reason.

**Amazon IP reputation — `AWSManagedRulesAmazonIpReputationList`, WCU 25, namespace `amazon-ip-list`.**

| Rule | Label | Action |
|---|---|---|
| `AWSManagedIPReputationList` | `awswaf:managed:aws:amazon-ip-list:AWSManagedIPReputationList` | **Block** |
| `AWSManagedReconnaissanceList` | `awswaf:managed:aws:amazon-ip-list:AWSManagedReconnaissanceList` | **Block** |
| `AWSManagedIPDDoSList` | `awswaf:managed:aws:amazon-ip-list:AWSManagedIPDDoSList` | **Count** |

`AWSManagedIPDDoSList` being **Count** is the single most consequential fact for the known-bad-IP
use case — see §7. The group carries no versioning and no SNS update notifications, and it uses the
**web request origin** address, so behind a proxy or another load balancer it sees the proxy.

**Anonymous IP — `AWSManagedRulesAnonymousIpList`, WCU 50, namespace `anonymous-ip-list`:**
`AnonymousIPList` and `HostingProviderIPList`, both Block.

"Known-bad" in these source rules therefore resolves to **the AWS managed IP reputation rule
group**, not to a customer `IPSet`. A customer IP set produces no label unless the customer's own
rule adds one with `RuleLabels`, so a label-matching rule cannot see a customer IP set by default —
that is a configuration a deployer must add deliberately.

---

## 7. Evaluation order, and why a two-signal rule usually cannot fire

Rules run in priority order. A rule with a **terminating** action ends evaluation immediately;
nothing after it runs, and nothing after it labels. Labels are visible only to rules that run
**after** the rule that added them.

Both signals of a "known-bad IP **and** web attack" rule therefore have to be added to **one
request in one evaluation**, and they land in the same record's `labels[]` array. There is no
correlation to do — but there is an ordering constraint that is fatal at defaults:

- If the IP reputation group runs **first** (the usual placement) and `AWSManagedIPReputationList`
  or `AWSManagedReconnaissanceList` matches, the action is **Block**, evaluation **stops**, and the
  CRS / SQLi / known-bad-inputs groups never run. **No attack label is ever added.**
- `AWSManagedIPDDoSList` is **Count**, so it labels and evaluation continues. This is the only one
  of the three reputation rules whose label can coexist with an attack label at defaults.
- If the reputation group runs **after** the attack groups, an attack that the attack group blocks
  terminates first and the reputation label is never added.

So the composite rule, at defaults, covers **one of its three reputation lists**, and it covers it
only when the attack rule that also matched did not terminate. Making it fire on the other two
requires the reputation group to be overridden to Count — which is a real and defensible
configuration (label-only reputation, block decided later), and one the rule silently depends on.

---

## 8. CloudTrail side

`eventSource` is `wafv2.amazonaws.com` for WAFv2; WAF Classic uses `waf.amazonaws.com` and
`waf-regional.amazonaws.com`. All WAF API calls are **management** events — there is no WAF data
event, and web requests never appear in CloudTrail in any configuration.

**Honest limit:** AWS's WAF CloudTrail page says only that *"CloudTrail captures a subset of API
calls for these services as events"* and does not enumerate which. It does not name the
`eventSource` string and does not publish per-event `requestParameters` shapes. So the event names
used in these playbooks — `PutLoggingConfiguration`, `DeleteLoggingConfiguration`, `UpdateWebACL`,
`DeleteWebACL`, `AssociateWebACL`, `DisassociateWebACL` — are the API operation names and are
expected to appear verbatim, but **that mapping is not documented by AWS and was not verified
against a captured event.** Playbooks say so where they depend on it, and every query that reads
these events routes an empty result to `[!] INCONCLUSIVE` rather than to a clean verdict.

WAFv2 resources come in two scopes: `REGIONAL` (ALB, API Gateway, AppSync, Cognito user pool,
App Runner, Verified Access) and `CLOUDFRONT`. **CloudFront-scope calls must be made against
`us-east-1`** (`--scope=CLOUDFRONT --region=us-east-1`), and their CloudTrail records land there.
A responder searching only the resource's own Region will miss every CloudFront-scope change.

`PutLoggingConfiguration` errors: `WAFInternalErrorException` (500),
`WAFInvalidParameterException` (400), `WAFInvalidOperationException` (400),
`WAFNonexistentItemException` (400), `WAFOptimisticLockException` (400),
`WAFLimitsExceededException` (400), `WAFLogDestinationPermissionIssueException` (400),
`WAFServiceLinkedRoleErrorException` (400),
`WAFFeatureNotIncludedInPricingPlanException` (400). Note `WAFNonexistentItemException` is a **400**,
not a 404. `GetSampledRequests` errors: `WAFInternalErrorException` (500),
`WAFInvalidParameterException` (400), `WAFNonexistentItemException` (400).

---

## 9. CloudWatch metrics

Namespace **`AWS/WAFV2`**, reported **once a minute**, and independent of web ACL logging.

Core metrics: `AllowedRequests`, `BlockedRequests`, `CountedRequests`, `PassedRequests`,
`CaptchaRequests`, `ChallengeRequests`, `RequestsWithValidCaptchaToken`,
`RequestsWithValidChallengeToken`, `CaptchasAttempted`, `CaptchasSolved`, `ChallengesAttempted`,
`ChallengesSolved`, `MonetizeRequests`, `MonetizeRequestsFailedVerification`. All are
`Sum`-valued, and all carry the reporting criterion *"There is a nonzero value"* — **a metric with
no datapoints means zero, not "unknown", but a metric that never existed and a metric that is zero
are indistinguishable through `get-metric-statistics` alone.**

Core dimensions: `WebACL`, `Rule`, `RuleGroup`, `Region`, `ResourceType`, `Resource`, `WebACLArn`,
`Country`, `Attack`, `Device`, `ManagedRuleGroup`, `ManagedRuleGroupRule`, `VulnerabilityCategory`,
`LoadBalancerArn`. The `Rule` dimension takes the rule's metric name, **`ALL`** for every rule in a
web ACL or rule group, or **`Default_Action`** (only with `WebACL`) for requests no rule terminated.

**Label metrics** are the ones that make a label countable without logs: dimensions
`LabelNamespace` and `Label`, with metrics `AllowedRequests`, `BlockedRequests`, `CountedRequests`,
`CaptchaRequests`, `ChallengeRequests`, and the `*RuleMatch` family. At most **100 labels per
request** are reflected in metrics.

Two gaps to know: *"Count action rules in rule groups do NOT emit web ACL dimension metrics — only
Rule, RuleGroup, and Region dimensions"*, and an ALB associated with a web ACL that has **no rules
or other active configurations** gets neither sampled requests nor CloudWatch metrics at all.

---

## 10. What could NOT be verified

- **Log delivery latency.** No AWS statement found on how long after a request its record appears
  in the destination. Every "no logs" threshold in these playbooks therefore has to allow for an
  undocumented delivery lag, and the no-logs playbook says so rather than picking a number.
- **CloudTrail event names for WAF.** See §8 — the operation names are expected, not documented.
- **Whether a `LoggingFilter` change emits a distinguishable CloudTrail record from any other
  logging-configuration change.** Both are `PutLoggingConfiguration`; whether
  `requestParameters.loggingConfiguration.loggingFilter` appears in the record was not verified
  against a captured event.
- **Maximum WAF log record size / truncation behaviour.** Not documented on the pages read. A very
  large header set may or may not be truncated in the record.
- **`GetSampledRequests` behaviour when `SampledRequestsEnabled` is false** — presumably empty, not
  documented.
- **The exact `httpRequest.headers` ordering guarantee.** Assumed to be request order; not stated.
- No AWS Config managed rule was found that asserts "web ACL logging is enabled". `AWS::WAFv2::LoggingConfiguration`
  exists as a CloudFormation resource type, which makes a custom Config rule practical, but no
  managed rule was confirmed.
