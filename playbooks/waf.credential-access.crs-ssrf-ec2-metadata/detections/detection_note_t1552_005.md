# Detection Note — T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)

**Signal:** a Core-rule-set `EC2MetaDataSSRF_*` label on a web request the web ACL evaluated —
somebody tried to make the application fetch `169.254.169.254` on their behalf.

**This is the only signal in the corpus that fires on an attempt rather than an outcome, and it
has to be read that way.** Everything else in the WAF set is the same, but here the gap is
unusually wide: a label says a pattern was present in an inbound request. It does not say the
application made the metadata call, does not say a credential came back, and cannot say either,
because the answer lives in the target instance's IMDSv2 setting and in CloudTrail rather than in
any web ACL log. The correct posture is that this alert is an **early** signal about an
application, and the credential-theft response it hands off to is
`../../ec2.credential-access.imds-credential-theft/`, which owns the outcome half — that the
metadata fetch itself produces no AWS telemetry at all, and that the credential's *use* is the
observable.

## What the four original rules got wrong

Four alerts — URI Path, Cookie, Body, Query Args — each `action:"ALLOW" AND labels ~
EC2MetaDataSSRF_<Component>`, each P2, threshold 0 over 5 minutes, grouped by
`httpRequest.clientIp`. Three defects, in order of cost.

**The `action:"ALLOW"` filter inverts the control.** All four `EC2MetaDataSSRF_*` rules in
`AWSManagedRulesCommonRuleSet` carry **Rule action: Block**. In a web ACL running the Core rule set
at its defaults, the attempt is blocked, `action` is `BLOCK`, and none of the four alerts fires.
They produce output only where the rule group has been overridden to Count or the rule excluded —
that is, only where the protection is off. And because nothing in the source set watches the
blocked stream, the attacker is invisible precisely when the control worked. A control whose alert
queue is empty in both the working case and the never-deployed case cannot be audited from the
queue. The terminating action is the **verdict axis**, not the filter: `sigma_t1552_005.yml` ships
`waf_ssrf_imds_reached` at `high` and `waf_ssrf_imds_stopped` at `low`, over the same label set.

**`CAPTCHA` and `CHALLENGE` are also terminating**, and neither reached the application. AWS:
*"The CAPTCHA and Challenge actions are terminating when the web request doesn't contain a valid
token."* A record reading `action: "CAPTCHA"` with `responseCodeSent: 405` and
`captchaResponse.failureReason: "TOKEN_MISSING"` is a stopped request. The inverse is the one that
catches people out: a CAPTCHA rule matching a request that *does* carry a valid token is
non-terminating, the top-level `action` reads `ALLOW`, and the CAPTCHA match appears under
`nonTerminatingMatchingRules`. That request **did** reach the application and is correctly counted
as reached.

**Four alerts for one observable.** One actor probing the URI path, then the query string, then
the body arrives as three unrelated P2 alerts against the same client address, and the pattern that
matters — *this client is enumerating where the application is injectable* — is the one the split
destroys. The count of **distinct components** per client is shipped here as a `value_count`
correlation at `high`, and it exists only because the four rules were merged.

**One further inconsistency, recorded rather than corrected:** three of the four source rules carry
`T1552.005` and the Body rule carries the bare parent `T1552`, inside one set of four siblings.
All four are the same technique.

## The label strings, and why there is no shortcut

| CRS rule name | Emitted label |
|---|---|
| `EC2MetaDataSSRF_BODY` | `awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_Body` |
| `EC2MetaDataSSRF_COOKIE` | `awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_Cookie` |
| `EC2MetaDataSSRF_QUERYARGUMENTS` | `awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_QueryArguments` |
| `EC2MetaDataSSRF_URIPATH` | `awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_URIPath` |

Labels are **case-sensitive**, and the label is not derivable from the rule name. Title-casing
`_URIPATH` gives `Uripath` and matches nothing; title-casing `_QUERYARGUMENTS` gives
`Queryarguments` and matches nothing. Nor is `_URIPath` a reliable house style — the SQL database
rule group spells `SQLi_URIPath` and `SQLiExtendedPatterns_UriPath` side by side, and the WordPress
group leaves its labels in screaming case entirely. The source rules match the label form, which is
**correct**; the hazard is a deployer who copies the rule name out of the managed-rule-group
documentation. The rules here match the component-independent stem
`core-rule-set:EC2MetaDataSSRF_` and read the component off the matched label, which is the only
shape that survives a casing surprise in either direction.

## The body variant, and only the body variant, has a size limit

`EC2MetaDataSSRF_BODY` inspects the body only up to the web ACL's body inspection limit:
**8 KB, fixed and not adjustable, for Application Load Balancer and AWS AppSync**; 16 KB by default
and up to 64 KB for CloudFront, API Gateway, Amazon Cognito, App Runner and Verified Access. It
uses the **`Continue`** oversize option, so AWS WAF inspects what fits and the rest is not
inspected — while *"the entire web request is sent, including any contents that are outside of the
count and size limits that AWS WAF was able to inspect."* Padding a POST body with 8 KB of filler
in front of the payload therefore defeats the body rule on an ALB-fronted application, and the log
shows the shape of it: `oversizeFields` carrying `REQUEST_BODY` or `REQUEST_JSON_BODY` on a request
that produced no `_Body` label.

**This caveat is the body rule's alone.** `_URIPath`, `_QueryArguments` and `_Cookie` do not
inspect the body. The compensating control is `SizeRestrictions_BODY`, also in the Core rule set,
Block by default, which rejects bodies over 8,192 bytes — if it is present and not overridden, the
padding trick is blocked before the body rules run, and its absence is worth checking before
writing off the body coverage.

## Field shape

The web ACL log is **not CloudTrail** and does not appear in it. It is its own record, delivered
only if `wafv2:PutLoggingConfiguration` was called for that web ACL — logging is **off by default**.

`labels` is an **array of single-key objects**, `[{"name": "<label>"}]`, not an array of strings;
the path is `labels[].name`. `httpRequest` is nested: `.clientIp`, `.country`, `.uri`, `.args`,
`.httpMethod`, `.httpVersion`, `.requestId`, and `.headers` as an array of `{"name","value"}`.
**There is no `httpRequest.host`** — the Host value has to be picked out of the headers array.
`webaclId` holds the web ACL **ARN**. `terminatingRuleId` is the literal `Default_Action` when no
rule terminated the request.

`terminatingRuleMatchDetails` and `ruleMatchDetails` are **empty for these rules**. AWS populates
them *"only for SQL injection and cross-site scripting (XSS) match rule statements"*, and
`EC2MetaDataSSRF_*` is a byte/regex match. Any triage flow expecting `matchedData` for a metadata
SSRF gets an empty array; the payload comes from `httpRequest.uri` and `.args`, and for the body
variant it does not come from WAF at all, because **WAF does not log request bodies**.

## Response levers

**GuardDuty and posture controls:** There is no GuardDuty finding type for an inbound SSRF pattern — GuardDuty observes the AWS control
plane and network, not web request content. The finding types that matter here fire on the *other*
side of this technique, when the stolen credential is used:
`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` and `.InsideAWS`. Those are
the alerting bullets of `../../ec2.credential-access.imds-credential-theft/`, not of this
playbook, and their absence here is the point: a WAF label is not evidence of theft, and a
GuardDuty exfiltration finding is not evidence of SSRF.

No AWS Config managed rule asserts "the Core rule set is not overridden to Count". The
configuration is read live with `aws wafv2 get-web-acl`, which is Query 2 of `../PLAYBOOK.md`.

**Severity:** **High** when the terminating action is `ALLOW` — not because a credential is known to have been
taken, but because an `ALLOW` on this label means the CRS default was overridden and the
application was handed the payload. **Medium** for sustained stopped attempts from one client,
**high** for two or more components from one client whether stopped or not, **low** for an isolated
blocked attempt. The source rates all four **P2** uniformly, which under-rates the served case and
over-rates a single background scan — and, because of the `ALLOW` filter, never emits the low one
at all.

**MITRE:** `T1552.005 — Unsecured Credentials: Cloud Instance Metadata API`, which is the source's own mapping on three of its four rules; the fourth maps to the parent `T1552` and is narrowed here for consistency. Verified live 2026-08-30.

**GuardDuty:** no finding type covers AWS WAF. GuardDuty has no WAF resource type at all, so nothing here is duplicated by it — these rules are the only coverage for this technique.

**Files here:**

- `sigma_t1552_005.yml` — four documents: `waf_ssrf_imds_reached` at `high` (label plus a
  terminating action of `ALLOW`); `waf_ssrf_imds_stopped` at `low` (the same labels with `BLOCK`,
  `CAPTCHA` or `CHALLENGE` — the only document in this file that fires in a default web ACL); an
  `event_count` correlation at `medium` for five or more stopped attempts from one client address
  in an hour; and a `value_count` correlation at `high` over both rules for two or more distinct
  component labels from one client, which is the pattern the four-way source split hid.
- `kql_t1552_005.kql` — scores the terminating action instead of filtering on it, recovers the
  component from the matched label, counts distinct components per client, extracts Host and
  User-Agent out of the headers array, and flags the oversize-body evasion. It also joins the
  client's other web ACL activity in the window, which is what separates a scanner from a targeted
  attempt.

Sibling notes: `../../ec2.credential-access.imds-credential-theft/detections/` owns the
outcome — the credential session used off-instance — and states the two facts this playbook depends
on and does not repeat: the metadata fetch produces no AWS telemetry, and VPC Flow Logs do not
record traffic to `169.254.169.254`. `../../waf.initial-access.sqli-body-detected/detections/`
shares the body-size caveat from the other direction.

Full response procedure is in `../PLAYBOOK.md`.
