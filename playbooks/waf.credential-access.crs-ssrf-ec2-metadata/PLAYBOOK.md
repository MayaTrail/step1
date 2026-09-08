# IR Playbook: EC2 Metadata SSRF at the Web ACL — `169.254.169.254` in an Inbound Request, Matched by the Core Rule Set `EC2MetaDataSSRF_*` Family

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Credential access attempt at the edge (a web request tries to make the application fetch the EC2 instance metadata service on the requester's behalf) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High** where the terminating action is `ALLOW` — not because a credential is known to have been taken, but because all four Core-rule-set `EC2MetaDataSSRF_*` rules are **Block** by default, so an `ALLOW` means the rule group was overridden to Count or the rule excluded, and the payload was handed to the application. **Medium** for repeated stopped attempts, **High** for two or more request components tried by one client, **Low** for an isolated blocked attempt. The four source rules rate everything **P2** and, because they gate on `action:"ALLOW"`, emit nothing at all in the configuration where the control is working |
| MITRE Tactics | Credential Access, Initial Access |
| MITRE Techniques | T1552.005 (primary), T1190 (secondary) — both verified live 2026-08-29 |
| Services in Scope | WAF (web ACL, managed rule groups, logging configuration), the protected resource (ALB, CloudFront, API Gateway, AppSync, Cognito, App Runner, Verified Access), EC2 (IMDS and instance profiles), IAM, CloudTrail, CloudWatch (metrics and Logs), Organizations (SCP) |

**What the technique does:** the actor sends a web request in which some component — the URI path, a query
argument, the body or a cookie — carries a reference to `169.254.169.254`, aiming to get the
application to issue that request server-side and return the response. The Core rule set inspects
four components with four separate rules, and on a match adds a label:
`awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_URIPath`, `_QueryArguments`, `_Body` or
`_Cookie`. Each of those rules has `Rule action: Block`, so at defaults the request terminates
there and the log carries `action: "BLOCK"`. If the rule group has been overridden to Count, or
that rule excluded, the label is still added, evaluation continues, and the request is served with
its payload intact. From there the attack leaves WAF's field of view entirely: whether the
application actually fetched the metadata endpoint, and whether it got a credential back, is
decided by the target instance's IMDSv2 configuration and is recorded in no web ACL log.

**Why the usual reflexes miss it.** The first reflex is to read an empty alert queue as absence of
the technique. It is not: the source rules require `action:"ALLOW"`, the managed rules block by
default, and the blocked stream is watched by nothing — so the queue is empty both when the control
is working and when the rule was never deployed, and those two states are indistinguishable from
the queue. The second reflex is to treat the alert as evidence of theft and start rotating
credentials. It is not that either: this is an inbound *attempt*, and the four source alerts
observe a signature, never an outcome. The third reflex is to go looking for the metadata fetch in
VPC Flow Logs, which do not record traffic to `169.254.169.254` at all — that ground is covered by
`../ec2.credential-access.imds-credential-theft/`, and this playbook does not repeat it.

**Detection thesis.** The discriminator is the **terminating action, read as a verdict rather than
used as a filter**, paired with the **count of distinct component labels from one client address**.
`ALLOW` means the protection is off for that rule and the payload was served; `BLOCK`, `CAPTCHA`
and `CHALLENGE` all mean stopped; two or more distinct components from one address means the client
is enumerating where the application is injectable rather than firing one opportunistic payload.
The source rules capture neither: they discard the entire stopped stream, and they split the one
observable into four alerts that nothing joins.

> The outcome half — a role session used from an address the instance cannot egress through — is
> `../ec2.credential-access.imds-credential-theft/`. It establishes that the metadata fetch
> produces no AWS telemetry and that the credential's *use* is the observable; §2 Query 4 here
> hands off to it rather than restating it. The body-size caveat below is shared with
> `../waf.initial-access.sqli-body-detected/`, and every query here presupposes
> `../waf.stealth.no-logs-from-aws-waf/` — a web ACL with no logging configuration produces none of
> this evidence.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **A web ACL logging configuration on every web ACL.** WAF traffic logs are **not CloudTrail**,
  they do not appear in it, and **logging is off by default** — it exists only where
  `wafv2:PutLoggingConfiguration` has been called for that specific web ACL. The destination is a
  CloudWatch Logs log group, an S3 bucket or a Firehose stream whose **name must begin with
  `aws-waf-logs-`**, in the same Region and account as the web ACL, and there is **one destination
  per web ACL**
- The record's shape, which every query below depends on: `labels` is an **array of single-key
  objects** — `[{"name": "<label>"}]`, path `labels[].name`, first 100 labels only.
  `httpRequest` is nested: `.clientIp`, `.country`, `.uri`, `.args`, `.httpMethod`, `.requestId`,
  and `.headers` as an array of `{"name","value"}`. **There is no `httpRequest.host`** — Host comes
  out of that array. `action` carries the terminating action, uppercase. `terminatingRuleId` is the
  literal `Default_Action` when nothing terminated. `webaclId` holds the web ACL **ARN**
- **`terminatingRuleMatchDetails` and `ruleMatchDetails` will be empty for these rules.** AWS
  populates them only for SQL-injection and XSS match statements; `EC2MetaDataSSRF_*` is a
  byte/regex match, so there is no `matchedData` and the payload has to come from `httpRequest.uri`
  and `.args`. **WAF does not log request bodies at all**
- CloudWatch metrics in `AWS/WAFV2`, which are reported once a minute and are **independent of
  logging** — `AllowedRequests`, `BlockedRequests`, `CountedRequests`, plus the **label metrics**
  with `LabelNamespace` and `Label` dimensions, which make an `EC2MetaDataSSRF_*` match countable
  even where the traffic log is missing. Governed by `VisibilityConfig.CloudWatchMetricsEnabled`
- CloudTrail multi-region trail capturing `wafv2.amazonaws.com` **management** events, so a change
  to the rule-group override or to the logging configuration is attributable. **CloudFront-scope
  web ACLs are managed through `us-east-1` and their events land there** — a responder searching
  only the resource's own Region misses every CloudFront-scope change
- **A recorded list of the CRS override state per web ACL**, held as data. The single fact that
  turns a `BLOCK` stream into an `ALLOW` stream is `OverrideAction: Count` on the rule group or a
  `RuleActionOverride` to Count on one of the four rules, and nothing alerts on it by default

**Alerting (must be pre-configured)**
- **A Core Rule Set `EC2MetaDataSSRF_*` label on a request whose terminating action is `ALLOW` → P0**
- **Two or more distinct `EC2MetaDataSSRF_*` component labels from one client address within an hour → P1**
- **`UpdateWebACL` setting the Core rule set to Count, or a `RuleActionOverride` to Count on an `EC2MetaDataSSRF_*` rule → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, held outside any principal or instance profile
  under investigation. `jq`
- The **Region and scope of every web ACL**, written down. `wafv2` calls need `--scope REGIONAL` or
  `--scope CLOUDFRONT`, and the CloudFront scope must be called against `--region us-east-1`
- A **pre-created, empty IP set** per web ACL with a rule already referencing it at the lowest
  numeric priority. Creating the IP set, adding the rule and re-ordering priorities during an
  incident means an `update-web-acl` that replaces the entire rule array under time pressure; a
  pre-wired empty set turns containment into a single `update-ip-set`
- A saved copy of each web ACL's `get-web-acl` output. `update-web-acl` **replaces the whole
  configuration** and requires the current `LockToken`; without a saved copy, a rollback is a
  reconstruction

**Known IOC Baselines**
- The egress addresses of authorised scanners and pen-test tooling, so an expected finding is
  excluded by `httpRequest.clientIp` and never by relaxing the label match
- The instance profiles reachable behind each protected resource, and their permissions. The web
  ACL log names a client address and a `httpSourceId`; it never names the instance or the role, so
  the mapping has to exist in advance or it is assembled during the incident
- The fleet's IMDSv2 state — `HttpTokens` and `HttpPutResponseHopLimit` per instance. An instance
  with `HttpTokens: required` makes this entire technique inert against it, and knowing which ones
  do not is the difference between a page and an acknowledgement

---

## 2. Identification

### Detection Triggers — HIGH

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | An `EC2MetaDataSSRF_*` label on a request whose terminating `action` is `ALLOW` | Web ACL traffic log | T1552.005 |
| P1 | Two or more distinct `EC2MetaDataSSRF_*` component labels from one `httpRequest.clientIp` within an hour | Web ACL traffic log | T1552.005 |
| P1 | `UpdateWebACL` setting `AWSManagedRulesCommonRuleSet` to `OverrideAction: Count`, or a `RuleActionOverride` to Count on an `EC2MetaDataSSRF_*` rule | CloudTrail (management, `wafv2.amazonaws.com`) | T1190 |

### Detection Triggers — MEDIUM and below

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Five or more `EC2MetaDataSSRF_*` labelled requests from one client address in an hour, all stopped | Web ACL traffic log | T1552.005 |
| P2 | `oversizeFields` containing `REQUEST_BODY` or `REQUEST_JSON_BODY` on traffic from a client that also produced an SSRF label — the body-limit evasion | Web ACL traffic log | T1190 |
| P2 | A `Label` dimension metric for `EC2MetaDataSSRF_*` with a nonzero value while the traffic log shows nothing — logging is broken, filtered or redacted | CloudWatch `AWS/WAFV2` label metrics | T1552.005 |
| P3 | A single `EC2MetaDataSSRF_*` labelled request, stopped — consistent with internet background scanning | Web ACL traffic log | T1552.005 |
| P3 | An instance-profile role session appearing from a source address outside the fleet's egress set | CloudTrail (management) | T1552.005 |

### Detection Rule Quality Notes

Four alerts that are one rule with a field varying, and a filter that switches the whole set off in
the configuration where the control is working.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `action:"ALLOW"` used as a filter, against four managed rules whose action is **Block** | In a web ACL running the Core rule set at defaults, none of the four alerts ever fires. They emit only where the rule group is overridden to Count or the rule excluded. A blocked attempt raises nothing at all, so the alert queue is empty both when the control works and when it was never deployed, and those two states cannot be told apart from the queue | Ship two rules over the same label set: `ALLOW` at `high`, `BLOCK`/`CAPTCHA`/`CHALLENGE` at `low` with volume correlations. Terminating action is the verdict axis |
| `CAPTCHA` and `CHALLENGE` unaccounted for | Both are terminating when the request carries no valid token, so a `CAPTCHA` record is a **stopped** request that the `ALLOW` filter drops and a naive "not BLOCK" rule would count as reached. The inverse also bites: a CAPTCHA rule matching a request that *has* a valid token is non-terminating and the record reads `ALLOW`, which genuinely did reach the application | Enumerate all four terminating values explicitly. Never write the stopped test as `not ALLOW` or the reached test as `not BLOCK` |
| One alert per request component, four times | One actor probing the URI path, the query string and the body arrives as three unrelated P2 alerts against the same client address, and the pattern that matters — enumeration of the injection point — is exactly what the split destroys. Worse, a single request carrying two of the four labels produces two alerts for one request | Merge. Carry the component as a field and count **distinct components** per client address; `value_count >= 2` is `high` |
| Nothing observes the outcome | All four watch an inbound signature. Whether a credential was returned is decided by the instance's `HttpTokens` setting, which is in no web ACL log, and the metadata fetch produces no AWS telemetry. A credential taken by code execution rather than SSRF produces no inbound signature at all | Treat this as an early signal, pivot to CloudTrail for the credential's use, and hand off to `../ec2.credential-access.imds-credential-theft/` |
| The body variant's size limit is unstated | `EC2MetaDataSSRF_BODY` inspects only the first **8 KB on an ALB or AppSync** — fixed, not adjustable — with `Continue` oversize handling, and the entire body is forwarded regardless. A payload behind 8 KB of padding defeats the rule silently, and the alert's absence reads as absence of the attack | Alert on `oversizeFields` carrying `REQUEST_BODY` where no body label was added; confirm `SizeRestrictions_BODY` is present and not overridden |
| Inconsistent MITRE mapping inside one set of four siblings | Three rules carry `T1552.005`, the Body rule carries the bare parent `T1552`. Mapping-precision, not a firing defect, but it fragments any technique-based reporting across the four | One primary, `T1552.005`, plus `T1190` for the vector |

**Recommended detection — a metadata SSRF payload that was served to the application.**

```yaml
# EC2 Metadata SSRF Observed at the Web ACL (T1552.005 / T1190)
#
# WHAT THE FOUR SOURCE RULES DO. Four separate alerts, one per request component - URI path,
# query arguments, body, cookie - each `action:"ALLOW" AND labels ~ EC2MetaDataSSRF_<Component>`,
# each P2, each threshold 0 over 5m, each grouped by `httpRequest.clientIp`. They are one rule
# with a field varying, and they are shipped here as one.
#
# THE `action:"ALLOW"` FILTER IS THE DEFECT, AND IT INVERTS THE CONTROL. All four
# `EC2MetaDataSSRF_*` rules in the Core rule set carry `Rule action: Block`. In a web ACL running
# the CRS at its defaults, a metadata SSRF attempt is blocked, evaluation terminates, `action` is
# `BLOCK`, and the source rules do not fire. They produce output only where the rule group has
# been overridden to Count or the rule excluded - i.e. only where the protection is OFF. And
# because nothing watches the blocked stream, the attacker is invisible precisely when the control
# worked. Terminating action belongs in the rule as a VERDICT AXIS, which is why this file ships
# two rules over the same label set rather than one rule with a filter.
#
# CAPTCHA AND CHALLENGE ARE TERMINATING ACTIONS. AWS: "The CAPTCHA and Challenge actions are
# terminating when the web request doesn't contain a valid token." A record with
# `action: "CAPTCHA"` did NOT reach the application, so it belongs with BLOCK and not with ALLOW.
# The mirror case matters too: a CAPTCHA rule matching a request that HAS a valid token is
# non-terminating and the record reads `action: "ALLOW"` with the CAPTCHA match under
# `nonTerminatingMatchingRules` - that request did reach the application.
#
# THE LABEL STRINGS ARE EXACT AND THERE IS NO TRANSFORM FROM THE RULE NAME. The CRS rule names are
# `EC2MetaDataSSRF_BODY`, `_COOKIE`, `_URIPATH`, `_QUERYARGUMENTS`; the labels they emit are
# `...:EC2MetaDataSSRF_Body`, `_Cookie`, `_URIPath`, `_QueryArguments`. Title-casing the rule name
# yields `Uripath` and `Queryarguments` and matches nothing - and the same rule group family that
# spells `SQLi_URIPath` also spells `SQLiExtendedPatterns_UriPath`, so there is no consistent
# transform to write. The rules below match the component-independent stem and carry the component
# out as a field, which is the only shape that survives a casing surprise.
#
# THE BODY VARIANT HAS A SIZE LIMIT AND THE OTHER THREE DO NOT. `EC2MetaDataSSRF_BODY` inspects
# the body only up to the web ACL's body limit - 8 KB FIXED for Application Load Balancer and
# AppSync, 16 KB by default and up to 64 KB for CloudFront, API Gateway, Cognito, App Runner and
# Verified Access - and uses the `Continue` oversize option, so anything past the limit is not
# inspected while the whole body is still forwarded to the application. `oversizeFields`
# containing `REQUEST_BODY` on a request with no body label is that evasion, visible in the log.
#
# WHAT NONE OF THIS OBSERVES. A label on an inbound request is an ATTEMPT. Whether a credential
# was actually retrieved is decided by the target instance's IMDSv2 enforcement, which is not in
# any web ACL log, and the credential's USE is the only observable outcome - see
# ../../ec2.credential-access.imds-credential-theft/ for that half.
title: EC2 metadata SSRF reached the application through the web ACL
id: a7daa41e-a0aa-4b1a-b5e4-cec5d2d2c439
name: waf_ssrf_imds_reached
status: experimental
description: >-
  A web request carrying an Amazon EC2 instance metadata SSRF pattern was matched by the Core rule
  set and was still served to the protected application. The Core rule set blocks these by default,
  so a terminating action of ALLOW means the rule group is overridden to Count, the rule is
  excluded, or a later rule allowed the request - the protection is off for this rule.
references:
  - https://attack.mitre.org/techniques/T1552/005/                                                 # retrieved 2026-08-29
  - https://attack.mitre.org/techniques/T1190/                                                     # retrieved 2026-08-29
  - https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html    # retrieved 2026-08-29
  - https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html                      # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.initial-access
  - attack.t1552.005
  - attack.t1190
logsource:
  product: aws
  service: waf
detection:
  ssrf_label:
    labels.name|contains: 'core-rule-set:EC2MetaDataSSRF_'
  reached:
    action: 'ALLOW'
  condition: ssrf_label and reached
falsepositives:
  - >-
    A security test or an authorised scanner replaying metadata-service payloads. Distinguishable
    by source address, not by payload - record the tester's egress addresses and exclude by
    httpRequest.clientIp, never by relaxing the label match.
  - >-
    An application that legitimately accepts a URL parameter naming 169.254.169.254 - vanishingly
    rare, and if it exists it is the vulnerability rather than the false positive.
level: high
---
# The blocked stream, which the source rules discard entirely. A single blocked attempt is not an
# incident; a client sending them repeatedly is a client that has an SSRF primitive and is working
# the payload space, and that is the earliest warning this technique offers. Kept at `low` as a
# single event, escalated by the correlations below. This is also the ONLY rule in this file that
# fires in a default web ACL, because the Core rule set blocks by default.
title: EC2 metadata SSRF stopped at the web ACL
id: 3f4f3e14-df62-4d5d-aa44-4d46ef27166d
name: waf_ssrf_imds_stopped
status: experimental
description: >-
  A web request carrying an EC2 instance metadata SSRF pattern was matched by the Core rule set and
  stopped - blocked, or answered with a CAPTCHA or Challenge interstitial. The request did not
  reach the application. Volume, not the single event, is the signal.
references:
  - https://attack.mitre.org/techniques/T1552/005/                                                 # retrieved 2026-08-29
  - https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html                      # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.t1552.005
logsource:
  product: aws
  service: waf
detection:
  ssrf_label:
    labels.name|contains: 'core-rule-set:EC2MetaDataSSRF_'
  stopped:
    action:
      - 'BLOCK'
      - 'CAPTCHA'
      - 'CHALLENGE'
  condition: ssrf_label and stopped
falsepositives:
  - >-
    Internet background scanning. Common and expected on any public endpoint; it is why this rule
    is `low` alone and meaningful only in volume from one client.
level: low
---
# THRESHOLD BASIS, with no observed baseline. A metadata SSRF payload is not a mistype and not a
# crawler artefact: reaching 169.254.169.254 has no benign reason to appear in a web request at
# all. Background scanning does produce isolated hits, so a single blocked attempt stays `low`;
# five from one client address inside an hour is somebody iterating encodings and components
# against a target they believe is vulnerable. `gte`, never `gt`, so a run of exactly five does
# not fall through. Re-baseline against this endpoint's own scan volume before deploying.
title: Repeated EC2 metadata SSRF attempts from one client address
id: 0cd66377-dcfc-4412-a081-10a1aacb298e
status: experimental
description: >-
  One client address sent five or more EC2 metadata SSRF requests that the web ACL stopped, within
  one hour. The control is holding, and somebody is working the payload space against it.
references:
  - https://attack.mitre.org/techniques/T1552/005/   # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.t1552.005
correlation:
  type: event_count
  rules:
    - waf_ssrf_imds_stopped
  group-by:
    - httpRequest.clientIp
  timespan: 1h
  condition:
    gte: 5
level: medium
---
# The four source rules made this pattern invisible by splitting it four ways: one actor probing
# the URI path, the query string and the body arrived as three unrelated P2 alerts against the same
# client address. Distinct LABELS from one client is the signal the split destroyed - two or more
# components means deliberate enumeration of where the application is injectable, not a single
# opportunistic payload. Counting labels rather than events also survives the case where one
# request carries two of the four labels at once.
title: EC2 metadata SSRF probed across multiple request components by one client
id: 1f7ee551-3387-4dea-ae80-1eccd593e9f9
status: experimental
description: >-
  One client address caused two or more distinct EC2MetaDataSSRF component labels within an hour -
  the URI path, query arguments, body or cookie tried in turn. That is enumeration of the
  injection point, and the four source rules reported it as unrelated alerts.
references:
  - https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html   # retrieved 2026-08-29
tags:
  - attack.credential-access
  - attack.t1552.005
correlation:
  type: value_count
  rules:
    - waf_ssrf_imds_stopped
    - waf_ssrf_imds_reached
  group-by:
    - httpRequest.clientIp
  field: labels.name
  timespan: 1h
  condition:
    gte: 2
level: high
```

The rule cannot see an SSRF that never names the metadata address in the request — an open
redirect, a DNS name resolving to `169.254.169.254`, or a stored second-order injection produce no
label at all. It cannot see a body payload past the inspection limit. And it cannot say whether a
credential came back: that is `HttpTokens` on the target instance, which Query 3 reads live, and
the credential's use, which Query 4 pivots to.

---

### Key Investigation Queries

> WAF is regional except for CloudFront-scope web ACLs, which are managed through `us-east-1`. WAF traffic logs are **not** CloudTrail and are not read with `lookup-events` — Query 1 reads the log group. **`lookup-events` returns ≤50 events per page**; paginate on `NextToken`.

#### Query 1 — Reconstruct: every metadata SSRF attempt, its component, and whether it was served

```bash
REGION="us-east-1"
LOG_GROUP="aws-waf-logs-<your-web-acl>"    # the destination name must begin with aws-waf-logs-
START=$(( $(date -u +%s) - 604800 ))
END=$(date -u +%s)

# Does the log group exist at all? An absent group is NOT "no attempts" - it is the far more
# likely case that this web ACL never had a logging configuration. Routed to INCONCLUSIVE.
LG=$(aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP" \
       --region "$REGION" --output json 2>&1)
case "$LG" in
  *logGroupName*) echo "[OK] found log group $LOG_GROUP";;
  *logGroups*)    echo "[!] INCONCLUSIVE - no log group named $LOG_GROUP in $REGION. WAF logging is"
                  echo "    OFF BY DEFAULT and this may never have been enabled. Nothing below can"
                  echo "    run; see ../waf.stealth.no-logs-from-aws-waf/ and use Query 5 instead."
                  exit 0;;
  *)              echo "[!] INCONCLUSIVE - could not list log groups: $LG"; exit 0;;
esac

# labels is an ARRAY OF OBJECTS. Insights flattens it to labels.0.name, labels.1.name, ... so the
# match is on the flattened paths; a request can legitimately carry several of the four labels.
QID=$(aws logs start-query --region "$REGION" --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --limit 10000 \
  --query-string 'fields @timestamp, action, terminatingRuleId, httpSourceName, httpSourceId, httpRequest.clientIp, httpRequest.country, httpRequest.httpMethod, httpRequest.uri, httpRequest.args, oversizeFields, @message | filter @message like /core-rule-set:EC2MetaDataSSRF_/ | sort @timestamp asc' \
  --query 'queryId' --output text 2>&1)
case "$QID" in
  *[!a-f0-9-]*|"") echo "[!] INCONCLUSIVE - start-query did not return a query id: $QID"; exit 0;;
esac

STATUS="Running"
while [ "$STATUS" = "Running" ] || [ "$STATUS" = "Scheduled" ]; do
  sleep 3
  RES=$(aws logs get-query-results --query-id "$QID" --region "$REGION" --output json 2>&1)
  case "$RES" in
    *\"status\"*) STATUS=$(printf '%s' "$RES" | jq -r '.status');;
    *) echo "[!] INCONCLUSIVE - get-query-results failed: $RES"; exit 0;;
  esac
done
[ "$STATUS" = "Complete" ] || echo "[!] INCONCLUSIVE - query ended in $STATUS; results are partial."

if [ "$(printf '%s' "$RES" | jq -r '.results | length')" -eq 0 ]; then
  echo "[i] no EC2MetaDataSSRF_ label in $LOG_GROUP over the window. Confirm with the CloudWatch"
  echo "    LABEL metric before reading this as no attempts - a logging filter or redaction can"
  echo "    empty the stream while the metric still counts. See Query 5."
else
  # The final object below is what later steps consume: client_ip, component, action, resource.
  printf '%s' "$RES" | jq -r '[.results[] | (reduce .[] as $f ({}; .[$f.field] = $f.value))] |
    map({time: .["@timestamp"],
         client_ip: .["httpRequest.clientIp"],
         country:   .["httpRequest.country"],
         action:    .action,
         reached:   (if .action == "ALLOW" then "SERVED-TO-APPLICATION" else "stopped" end),
         terminating_rule: .terminatingRuleId,
         resource_type: .httpSourceName,
         resource_id:   .httpSourceId,
         method: .["httpRequest.httpMethod"],
         uri:    .["httpRequest.uri"],
         args:   .["httpRequest.args"],
         oversize: (.oversizeFields // "none"),
         component: ((.["@message"] | capture("EC2MetaDataSSRF_(?<c>[A-Za-z]+)").c) // "unparsed")})'
fi
```

Read `reached` first. `SERVED-TO-APPLICATION` on any row is the P0: the Core rule set blocks these
by default, so an `ALLOW` says the rule group is overridden to Count or the rule is excluded, and
Query 2 settles which. Then count **distinct `component` values per `client_ip`** — one is an
opportunistic payload, two or more is enumeration of the injection point. `oversize` carrying
`REQUEST_BODY` on a client that also produced SSRF labels is the body-limit evasion. Record
`client_ip`, `resource_id`, `uri` and `args` as IOCs, and carry `client_ip` into Steps 2 and 4.
`args` is the query string and is present; the **body is not in the log** and never will be.

#### Query 2 — Inspect the web ACL: is the Core rule set actually blocking?

```bash
REGION="us-east-1"; SCOPE="REGIONAL"        # CLOUDFRONT web ACLs: SCOPE=CLOUDFRONT and REGION=us-east-1
ACL_NAME="<web-acl-name>"
ACL_ID=$(aws wafv2 list-web-acls --scope "$SCOPE" --region "$REGION" \
           --query "WebACLs[?Name=='$ACL_NAME'].Id | [0]" --output text 2>&1)
case "$ACL_ID" in
  ""|None|*error*) echo "[!] INCONCLUSIVE - no web ACL named $ACL_NAME in scope $SCOPE / $REGION: $ACL_ID"; exit 0;;
esac

ACL=$(aws wafv2 get-web-acl --name "$ACL_NAME" --scope "$SCOPE" --id "$ACL_ID" \
        --region "$REGION" --output json 2>&1)
case "$ACL" in
  *LockToken*) echo "[OK] read web ACL $ACL_NAME";;
  *) echo "[!] INCONCLUSIVE - could not read the web ACL: $ACL"; exit 0;;
esac

# Is the Core rule set present, and is it blocking? OverrideAction.Count on the rule group turns
# every rule in it into a labelling-only rule. A RuleActionOverride to Count does the same to one.
CRS=$(printf '%s' "$ACL" | jq -c '[.WebACL.Rules[]
  | select(.Statement.ManagedRuleGroupStatement.Name == "AWSManagedRulesCommonRuleSet")]')
if [ "$CRS" = "[]" ]; then
  echo "[FAIL] AWSManagedRulesCommonRuleSet is NOT in this web ACL. The EC2MetaDataSSRF_ rules"
  echo "       cannot have produced the label; check which web ACL the alert actually came from."
else
  printf '%s' "$CRS" | jq -r '.[] |
    "rule_group=\(.Name) priority=\(.Priority) override=\(if .OverrideAction.Count then "COUNT - NOT BLOCKING" else "none - blocking" end)"'
  OVR=$(printf '%s' "$CRS" | jq -r '[.[] | select(.OverrideAction.Count)] | length')
  if [ "$OVR" -gt 0 ]; then
    echo "[FAIL] the Core rule set is overridden to Count. Every EC2MetaDataSSRF_ match is labelled"
    echo "       and ALLOWED. This is the explanation for any SERVED row in Query 1."
  else
    echo "[OK] no rule-group-wide Count override on the Core rule set"
  fi
  # Per-rule overrides, which the group-level check above does not see.
  PER=$(printf '%s' "$CRS" | jq -r '[.[].Statement.ManagedRuleGroupStatement.RuleActionOverrides[]?
    | select(.Name | startswith("EC2MetaDataSSRF_"))
    | "\(.Name) -> \(.ActionToUse | keys[0])"] | .[]')
  if [ -n "$PER" ]; then echo "[FAIL] per-rule overrides on the SSRF rules:"; printf '%s\n' "$PER"
  else echo "[OK] no per-rule override on any EC2MetaDataSSRF_ rule"; fi
fi

# SizeRestrictions_BODY is the compensating control for the body-limit evasion. It is Block by
# default and rejects bodies over 8,192 bytes; overridden to Count, the padding trick is open.
SZ=$(printf '%s' "$ACL" | jq -r '[.WebACL.Rules[].Statement.ManagedRuleGroupStatement.RuleActionOverrides[]?
  | select(.Name == "SizeRestrictions_BODY") | (.ActionToUse | keys[0])] | .[]')
if [ -n "$SZ" ]; then echo "[FAIL] SizeRestrictions_BODY is overridden to $SZ - oversize bodies pass"
else echo "[OK] SizeRestrictions_BODY carries no override (Block, if the Core rule set is present)"; fi

# The body inspection limit that actually applied. Absent AssociationConfig means the default:
# 8 KB fixed on ALB and AppSync, 16 KB elsewhere.
printf '%s' "$ACL" | jq -r '.WebACL.AssociationConfig.RequestBody // {} |
  if length == 0 then "body inspection limit: DEFAULT (8 KB fixed on ALB/AppSync, 16 KB otherwise)"
  else "body inspection limit set per resource type: \(.)" end'
```

An `OVR` greater than zero, or a per-rule override, is the whole explanation for a served payload
and is the thing §3 Step 1 reverses. A `[FAIL]` on `SizeRestrictions_BODY` means the padding
evasion is available in addition. This web ACL's logging configuration — the other reason Query 1
can come back empty — is read by Query 5 and asserted in §5.

#### Query 3 — Resolve the target: which resource, which instances, and is IMDSv2 enforced?

```bash
REGION="us-east-1"; SCOPE="REGIONAL"
ACL_ARN="<web-acl-arn>"
CLIENT_IP="<client-ip-from-Query-1>"
echo "[i] attempts from $CLIENT_IP are being traced to the resource behind $ACL_ARN"

# For a REGIONAL web ACL this lists the protected resources. For CLOUDFRONT scope it is not
# supported - the association is read from the distribution instead - so that path is called out
# rather than silently returning nothing.
if [ "$SCOPE" = "REGIONAL" ]; then
  RES=$(aws wafv2 list-resources-for-web-acl --web-acl-arn "$ACL_ARN" \
          --region "$REGION" --output json 2>&1)
  case "$RES" in
    *ResourceArns*) printf '%s' "$RES" | jq -r '.ResourceArns[]' | sed 's/^/  protected: /';;
    *) echo "[!] INCONCLUSIVE - list-resources-for-web-acl failed: $RES";;
  esac
else
  echo "[i] CLOUDFRONT scope: list-resources-for-web-acl does not apply. Find the distribution with"
  echo "    aws cloudfront list-distributions --query \"DistributionList.Items[?WebACLId=='$ACL_ARN'].Id\""
  RES=""
fi

# Behind an ALB the instances are the target group's targets, healthy and unhealthy alike - an
# unhealthy instance still holds a role.
LB_ARN=$(printf '%s' "$RES" | jq -r '.ResourceArns[]? | select(contains(":loadbalancer/app/"))' | head -1)
INSTANCES=""
if [ -n "$LB_ARN" ]; then
  TGS=$(aws elbv2 describe-target-groups --load-balancer-arn "$LB_ARN" --region "$REGION" \
          --query 'TargetGroups[].TargetGroupArn' --output text 2>&1)
  case "$TGS" in
    arn:*) for TG in $TGS; do
             INSTANCES="$INSTANCES $(aws elbv2 describe-target-health --target-group-arn "$TG" \
               --region "$REGION" --query 'TargetHealthDescriptions[].Target.Id' --output text 2>/dev/null)"
           done;;
    *) echo "[!] INCONCLUSIVE - could not list target groups for $LB_ARN: $TGS";;
  esac
fi

if [ -z "$(printf '%s' "$INSTANCES" | tr -d ' ')" ]; then
  echo "[!] INCONCLUSIVE - no EC2 instance ids resolved. The application may be Fargate, Lambda or"
  echo "    an IP-target group; IMDS applies only to EC2, and container tasks use the task"
  echo "    metadata endpoint instead. Establish the compute type by hand before concluding."
else
  # ORDERING CONSTRAINT: read MetadataNoToken BEFORE anything sets HttpTokens=required. AWS emits
  # MetadataNoToken and MetadataNoTokenRejected as mutually exclusive per instance, so after the
  # remediation this number is zero BY CONSTRUCTION and can never be recovered.
  for I in $INSTANCES; do
    case "$I" in i-*) ;; *) continue;; esac
    OPTS=$(aws ec2 describe-instances --instance-ids "$I" --region "$REGION" --output json 2>&1)
    case "$OPTS" in
      *HttpTokens*)
        printf '%s' "$OPTS" | jq -r '.Reservations[].Instances[] |
          (if .MetadataOptions.HttpTokens == "required"
           then "[OK] \(.InstanceId) HttpTokens=required" else "[FAIL] \(.InstanceId) HttpTokens=\(.MetadataOptions.HttpTokens) - IMDSv1 reachable by a plain GET" end)
          + " hop=\(.MetadataOptions.HttpPutResponseHopLimit) profile=\(.IamInstanceProfile.Arn // "none")"';;
      *) echo "[!] INCONCLUSIVE - could not read $I: $OPTS";;
    esac
    NOTOK=$(aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name MetadataNoToken \
              --dimensions Name=InstanceId,Value="$I" --statistics Sum --period 86400 \
              --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
              --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --region "$REGION" --output json 2>&1)
    case "$NOTOK" in
      *Datapoints*) printf '%s' "$NOTOK" | jq -r --arg i "$I" '.Datapoints | if length == 0
          then "[i] \($i): no MetadataNoToken datapoints - no IMDSv1 calls, or the metric is not reported"
          else "[FAIL] \($i): IMDSv1 calls in the window, Sum=\([.[].Sum] | add)" end';;
      *) echo "[!] INCONCLUSIVE - MetadataNoToken unreadable for $I: $NOTOK";;
    esac
  done
fi
```

`HttpTokens=required` on every instance makes this whole technique inert against that host — the
plain `GET` an SSRF can forge fails without a token from a prior `PUT` it cannot issue. A `[FAIL]`
here is what converts a stopped attempt into a live exposure. **Capture `MetadataNoToken` before
§3 Step 3 runs**: once `HttpTokens=required` is set, AWS reports `MetadataNoTokenRejected` instead
and this figure is unrecoverable. Carry the instance profile's role name into Query 4.

#### Query 4 — Pivot to the outcome: was the instance role's credential used off-instance?

```bash
REGION="us-east-1"
ROLE_NAME="<role-name-from-Query-3>"
EGRESS_CIDRS="203.0.113.0/24"     # this fleet's NAT / egress addresses, space-separated
RAW=$(aws cloudtrail lookup-events \
        --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
        --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
        --region "$REGION" --output json 2>&1)
case "$RAW" in
  *Events*) ;;
  *) echo "[!] INCONCLUSIVE - lookup-events returned no envelope: $RAW"; exit 0;;
esac

# An EC2 instance-profile session names the INSTANCE ID as its role session name, so every event a
# stolen credential produces carries, in its own ARN, the single host it may originate from.
# ec2RoleDelivery of 1.0 is the IMDSv1 path an SSRF can actually reach; 2.0 is IMDSv2.
SESS=$(aws cloudtrail lookup-events \
         --lookup-attributes AttributeKey=ResourceType,AttributeValue=AWS::IAM::Role \
         --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
         --region "$REGION" --output json 2>&1)
printf '%s' "$SESS" | jq -r --arg r "$ROLE_NAME" '.Events[]?.CloudTrailEvent | fromjson |
  select((.userIdentity.arn // "") | contains(":assumed-role/" + $r + "/")) |
  {time: .eventTime, event: .eventName, source: .eventSource,
   arn: .userIdentity.arn,
   instance_in_session: (.userIdentity.arn | split("/") | last),
   delivery: (.userIdentity.sessionContext.ec2RoleDelivery // "not-present"),
   src: .sourceIPAddress, agent: .userAgent, error: (.errorCode // "SUCCESS")}' \
  | jq -s 'if length == 0
      then {note: "no events found for this role in the window - this is NOT proof of no use; a management-only trail, the wrong region, or a role that calls nothing all produce this"}
      else (group_by(.arn) | map({session: .[0].arn, instance: .[0].instance_in_session,
                                  distinct_source_ips: (map(.src) | unique),
                                  delivery: (map(.delivery) | unique),
                                  events: length}))
    end'
echo "[i] The uncompromised baseline for distinct_source_ips per instance-profile session is ONE."
echo "    More than one address on a single session, or any address outside $EGRESS_CIDRS, is the"
echo "    finding. A delivery of 1.0 means the credential came out of IMDSv1 - the path an SSRF"
echo "    can reach. Full response for that case: ../ec2.credential-access.imds-credential-theft/"
```

This is the only query in the set that speaks to whether anything was actually taken. A session ARN
appearing from more than one source address, or from an address outside the fleet's egress set, is
the compromise; `ec2RoleDelivery` of `1.0` says the credential came from the IMDSv1 path an SSRF can
forge. An empty result is **not** proof of no use — it is routed to a note, not to a clean verdict.

#### Query 5 — Sweep: every web ACL in the account, its override state, and its logging

```bash
REGION="us-east-1"
for SCOPE in REGIONAL CLOUDFRONT; do
  R="$REGION"; [ "$SCOPE" = "CLOUDFRONT" ] && R="us-east-1"
  LIST=$(aws wafv2 list-web-acls --scope "$SCOPE" --region "$R" --output json 2>&1)
  case "$LIST" in
    *WebACLs*) ;;
    *) echo "[!] INCONCLUSIVE - list-web-acls failed for $SCOPE in $R: $LIST"; continue;;
  esac
  [ "$(printf '%s' "$LIST" | jq -r '.WebACLs | length')" -eq 0 ] && { echo "[i] no $SCOPE web ACLs in $R"; continue; }
  printf '%s' "$LIST" | jq -r '.WebACLs[] | "\(.Name)\t\(.Id)"' | while IFS="$(printf '\t')" read -r N I; do
    A=$(aws wafv2 get-web-acl --name "$N" --scope "$SCOPE" --id "$I" --region "$R" --output json 2>&1)
    case "$A" in
      *LockToken*) ;;
      *) echo "[!] INCONCLUSIVE - $SCOPE/$N unreadable: $A"; continue;;
    esac
    CRS=$(printf '%s' "$A" | jq -r '[.WebACL.Rules[] | select(.Statement.ManagedRuleGroupStatement.Name == "AWSManagedRulesCommonRuleSet")] |
            if length == 0 then "absent" elif any(.OverrideAction.Count; .) then "count" else "blocking" end')
    L=$(aws wafv2 get-logging-configuration --scope "$SCOPE" --region "$R" \
          --resource-arn "$(printf '%s' "$A" | jq -r '.WebACL.ARN')" --output json 2>&1)
    case "$L" in
      *LogDestinationConfigs*)       LOGS="on";;
      *WAFNonexistentItemException*) LOGS="OFF";;
      *)                             LOGS="unknown";;
    esac
    case "$CRS:$LOGS" in
      absent:*)     echo "[FAIL] $SCOPE/$N: no Core rule set - no EC2MetaDataSSRF_ coverage (logging=$LOGS)";;
      count:*)      echo "[FAIL] $SCOPE/$N: Core rule set OVERRIDDEN TO COUNT - labelling only (logging=$LOGS)";;
      blocking:on)  echo "[OK] $SCOPE/$N: Core rule set blocking, logging on";;
      *)            echo "[FAIL] $SCOPE/$N: Core rule set blocking, but logging=$LOGS - matches are invisible";;
    esac
  done
done
```

The question the incident makes worth asking of the whole account: how many other web ACLs are
labelling instead of blocking, and how many are blocking silently. Both are `[FAIL]` and they fail
in opposite directions — one has no protection, the other has no evidence.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Two ordering constraints, both of which destroy evidence if taken out of order. **Read
`MetadataNoToken` (Query 3) before setting `HttpTokens=required`** — AWS reports
`MetadataNoToken` and `MetadataNoTokenRejected` as mutually exclusive per instance, so after the
change the IMDSv1 call count is zero by construction and unrecoverable. And **save
`get-web-acl` output before any `update-web-acl`** — the update replaces the entire configuration
and consumes a `LockToken` that changes with every write, so without the saved copy there is no
rollback and no record of what the override was.

> Run under the **break-glass responder credentials** from §1.

#### Step 1 — Restore the blocking action on the Core rule set

```bash
REGION="us-east-1"; SCOPE="REGIONAL"; ACL_NAME="<web-acl-name>"
ACL_ID=$(aws wafv2 list-web-acls --scope "$SCOPE" --region "$REGION" \
           --query "WebACLs[?Name=='$ACL_NAME'].Id | [0]" --output text)
SNAP="/tmp/webacl-$ACL_NAME-$(date -u +%Y%m%dT%H%M%SZ).json"
aws wafv2 get-web-acl --name "$ACL_NAME" --scope "$SCOPE" --id "$ACL_ID" \
  --region "$REGION" --output json > "$SNAP" 2>&1
if ! jq -e '.LockToken' "$SNAP" >/dev/null 2>&1; then
  echo "[!] INCONCLUSIVE - could not snapshot the web ACL. DO NOT run update-web-acl without it:"
  echo "    the update replaces the whole configuration and there would be nothing to roll back to."
  cat "$SNAP"
else
  echo "[OK] snapshot saved to $SNAP - this is the rollback artefact"
  LOCK=$(jq -r '.LockToken' "$SNAP")
  # Strip the Count override off the Core rule set and any per-rule override on the SSRF rules.
  jq '.WebACL.Rules |= map(
        if .Statement.ManagedRuleGroupStatement.Name == "AWSManagedRulesCommonRuleSet"
        then (del(.OverrideAction) | .OverrideAction = {"None": {}}
              | .Statement.ManagedRuleGroupStatement.RuleActionOverrides =
                  ([.Statement.ManagedRuleGroupStatement.RuleActionOverrides[]?
                    | select((.Name | startswith("EC2MetaDataSSRF_")) | not)]))
        else . end)' "$SNAP" > "$SNAP.fixed"
  aws wafv2 update-web-acl --name "$ACL_NAME" --scope "$SCOPE" --id "$ACL_ID" \
    --region "$REGION" --lock-token "$LOCK" \
    --default-action "$(jq -c '.WebACL.DefaultAction' "$SNAP.fixed")" \
    --visibility-config "$(jq -c '.WebACL.VisibilityConfig' "$SNAP.fixed")" \
    --rules "$(jq -c '.WebACL.Rules' "$SNAP.fixed")" >/dev/null 2>&1 \
    && echo "[OK] Core rule set restored to Block; SSRF rule overrides removed" \
    || echo "[FAIL] update-web-acl did not succeed - the rule group is still labelling only. Check"
  echo "[i] If the override exists in IaC, this change is reverted by the next deploy. §4 owns that."
fi
```

#### Step 2 — Block the client address at the edge

```bash
REGION="us-east-1"; SCOPE="REGIONAL"
IPSET_NAME="ir-blocklist"                      # the pre-created set from §1, already referenced
CLIENT_IP="<client-ip-from-Query-1>"
SET_ID=$(aws wafv2 list-ip-sets --scope "$SCOPE" --region "$REGION" \
           --query "IPSets[?Name=='$IPSET_NAME'].Id | [0]" --output text 2>&1)
CUR=$(aws wafv2 get-ip-set --name "$IPSET_NAME" --scope "$SCOPE" --id "$SET_ID" \
        --region "$REGION" --output json 2>&1)
case "$CUR" in
  *LockToken*)
    NEW=$(printf '%s' "$CUR" | jq -r --arg ip "$CLIENT_IP/32" '[.IPSet.Addresses[], $ip] | unique | join(" ")')
    aws wafv2 update-ip-set --name "$IPSET_NAME" --scope "$SCOPE" --id "$SET_ID" \
      --region "$REGION" --lock-token "$(printf '%s' "$CUR" | jq -r '.LockToken')" \
      --addresses $NEW >/dev/null 2>&1 \
      && echo "[OK] $CLIENT_IP/32 added to $IPSET_NAME" \
      || echo "[FAIL] update-ip-set did not succeed - $CLIENT_IP is still reaching the edge";;
  *) echo "[!] INCONCLUSIVE - $IPSET_NAME is not readable: $CUR. Creating a set now also means"
     echo "    adding a rule and re-ordering priorities - a full update-web-acl under time"
     echo "    pressure. Do it, but snapshot first as in Step 1.";;
esac
echo "[i] An address block is a speed bump. It does not fix the application vulnerability and it"
echo "    does not survive the actor changing source. Steps 1 and 3 are the durable ones."
```

#### Step 3 — Enforce IMDSv2 on every instance behind the resource

```bash
REGION="us-east-1"
INSTANCES="<instance-ids-from-Query-3>"        # space-separated i-... from Query 3
echo "[i] Query 3 MUST have captured MetadataNoToken already. After this step that metric is zero"
echo "    by construction - AWS reports MetadataNoTokenRejected instead - and is unrecoverable."
for I in $INSTANCES; do
  case "$I" in i-*) ;; *) echo "[i] skipping non-instance token $I"; continue;; esac
  OUT=$(aws ec2 modify-instance-metadata-options --instance-id "$I" --region "$REGION" \
          --http-tokens required --http-endpoint enabled --http-put-response-hop-limit 1 \
          --output json 2>&1)
  case "$OUT" in
    *HttpTokens*) printf '%s' "$OUT" | jq -r --arg i "$I" '.InstanceMetadataOptions |
      if .HttpTokens == "required" then "[OK] \($i) HttpTokens=required (state=\(.State))"
      else "[FAIL] \($i) still reports HttpTokens=\(.HttpTokens) after the modify call" end';;
    *) echo "[FAIL] modify-instance-metadata-options failed for $I: $OUT";;
  esac
done
echo "[i] A hop limit of 1 stops a container on the host reaching IMDS through the host network."
echo "    If the application legitimately runs in a container that needs IMDS, 2 is the value -"
echo "    setting 1 there is an outage, so confirm the topology before applying it fleet-wide."
```

#### Step 4 — Contain the principal, if Query 4 showed the credential in use

```bash
ROLE_NAME="<role-name-from-Query-3>"
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EXISTS=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.RoleName' --output text 2>&1)
case "$EXISTS" in
  "$ROLE_NAME")
    aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name "EmergencyRevokeSessions" \
      --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}' \
      && echo "[OK] revoked pre-$CUTOFF sessions for $ROLE_NAME" \
      || echo "[FAIL] could not attach the revocation policy to $ROLE_NAME";;
  *) echo "[!] INCONCLUSIVE - no IAM role named $ROLE_NAME is readable from here: $EXISTS";;
esac
echo "[i] The revocation is defeated by a single re-fetch while the SSRF primitive survives, which"
echo "    is why Step 3 comes first. Full credential-compromise handling, including the instance"
echo "    profile replacement, is ../ec2.credential-access.imds-credential-theft/ §3."
```

---

## 4. Eradication

### Remove Attacker Access

- **Fix the override where it is declared, not where it is running.** If the Count override came
  from CloudFormation, Terraform or Firewall Manager, Step 1's change is reverted by the next
  deploy and the alert queue goes quiet again for the wrong reason. Grep the IaC for
  `OverrideAction` and `RuleActionOverride` against `AWSManagedRulesCommonRuleSet`, change it
  there, and confirm the deploy pipeline has run before closing.
- **Fix the SSRF itself.** The WAF rule is a pattern match on one spelling of one address. An
  application that will fetch an attacker-supplied URL remains exploitable through a DNS name that
  resolves to `169.254.169.254`, an open redirect, an alternate encoding, or IPv6
  `[fd00:ec2::254]`. The durable fix is an allowlist of the hosts the application may fetch,
  enforced after DNS resolution.
- **Make IMDSv2 the account default so a new instance is not a new exposure.** `HttpTokens=required`
  applied to running instances does nothing for the next launch; set it in the launch template and
  in the AMI's instance-metadata defaults so the fleet converges rather than drifting back.
- **Right-size the instance profile.** The severity of every future SSRF against this application
  is the permission set of the role on the host. A profile that can read one bucket and write one
  queue turns a credential theft into an inconvenience.
- **Restore `SizeRestrictions_BODY` to Block** if Query 2 found it overridden. Without it, the
  8 KB body limit on an ALB is an open evasion for the `_Body` rule and for every other body rule
  in the account.
- **Remove the emergency address block once the application fix has shipped, and assert it:**

```bash
REGION="us-east-1"; SCOPE="REGIONAL"; IPSET_NAME="ir-blocklist"
CLIENT_IP="<client-ip-from-Query-1>"
SET_ID=$(aws wafv2 list-ip-sets --scope "$SCOPE" --region "$REGION" \
           --query "IPSets[?Name=='$IPSET_NAME'].Id | [0]" --output text 2>&1)
CUR=$(aws wafv2 get-ip-set --name "$IPSET_NAME" --scope "$SCOPE" --id "$SET_ID" \
        --region "$REGION" --output json 2>&1)
case "$CUR" in
  *LockToken*)
    KEEP=$(printf '%s' "$CUR" | jq -r --arg ip "$CLIENT_IP/32" \
             '[.IPSet.Addresses[] | select(. != $ip)] | join(" ")')
    # An empty --addresses is a CLI error, not an empty set. Emptying the set needs the JSON form.
    if [ -n "$KEEP" ]; then
      aws wafv2 update-ip-set --name "$IPSET_NAME" --scope "$SCOPE" --id "$SET_ID" \
        --region "$REGION" --lock-token "$(printf '%s' "$CUR" | jq -r '.LockToken')" \
        --addresses $KEEP >/dev/null 2>&1
    else
      aws wafv2 update-ip-set --cli-input-json "$(printf '%s' "$CUR" | jq -c \
        --arg n "$IPSET_NAME" --arg s "$SCOPE" --arg i "$SET_ID" \
        '{Name:$n, Scope:$s, Id:$i, Addresses:[], LockToken:.LockToken}')" \
        --region "$REGION" >/dev/null 2>&1
    fi
    AFTER=$(aws wafv2 get-ip-set --name "$IPSET_NAME" --scope "$SCOPE" --id "$SET_ID" \
              --region "$REGION" --output json 2>&1)
    case "$AFTER" in
      *Addresses*)
        if [ "$(printf '%s' "$AFTER" | jq -r --arg ip "$CLIENT_IP/32" \
                 '[.IPSet.Addresses[] | select(. == $ip)] | length')" -eq 0 ]
        then echo "[OK] $CLIENT_IP/32 removed from $IPSET_NAME"
        else echo "[FAIL] $CLIENT_IP/32 is still in $IPSET_NAME"; fi;;
      *) echo "[!] INCONCLUSIVE - could not re-read $IPSET_NAME after the update: $AFTER";;
    esac;;
  *) echo "[!] INCONCLUSIVE - could not read $IPSET_NAME: $CUR";;
esac
```

- **Remove the session-revocation policy from the role once the credential is confirmed dead**, and
  assert its absence — an `EmergencyRevokeSessions` left attached silently breaks the workload the
  next time the role is used with an older token.

---

## 5. Recovery

### Restore Clean State

#### Verify the Core rule set is blocking again, on the web ACL that was changed

```bash
REGION="us-east-1"; SCOPE="REGIONAL"; ACL_NAME="<web-acl-name>"; VERDICT="clean"
ACL_ID=$(aws wafv2 list-web-acls --scope "$SCOPE" --region "$REGION" \
           --query "WebACLs[?Name=='$ACL_NAME'].Id | [0]" --output text 2>&1)
ACL=$(aws wafv2 get-web-acl --name "$ACL_NAME" --scope "$SCOPE" --id "$ACL_ID" \
        --region "$REGION" --output json 2>&1)
case "$ACL" in
  *LockToken*)
    HAS=$(printf '%s' "$ACL" | jq -r '[.WebACL.Rules[] | select(.Statement.ManagedRuleGroupStatement.Name == "AWSManagedRulesCommonRuleSet")] | length')
    OVR=$(printf '%s' "$ACL" | jq -r '[.WebACL.Rules[] | select(.Statement.ManagedRuleGroupStatement.Name == "AWSManagedRulesCommonRuleSet") | select(.OverrideAction.Count)] | length')
    PER=$(printf '%s' "$ACL" | jq -r '[.WebACL.Rules[].Statement.ManagedRuleGroupStatement.RuleActionOverrides[]? | select(.Name | startswith("EC2MetaDataSSRF_"))] | length')
    if   [ "$HAS" -eq 0 ]; then echo "[FAIL] the Core rule set is not in $ACL_NAME at all"; VERDICT="fail"
    elif [ "$OVR" -gt 0 ]; then echo "[FAIL] the Core rule set is still overridden to Count"; VERDICT="fail"
    elif [ "$PER" -gt 0 ]; then echo "[FAIL] $PER per-rule override(s) remain on EC2MetaDataSSRF_ rules"; VERDICT="fail"
    else echo "[OK] the Core rule set is present with no Count override and no SSRF rule override"; fi;;
  *) echo "[!] INCONCLUSIVE - could not re-read the web ACL: $ACL"; VERDICT="inconclusive";;
esac
```

This assertion survives the remediation because `get-web-acl` returns the whole rule array whatever
its state — a restored rule group reports `OverrideAction: {"None": {}}`, not an absence, so
`[FAIL]` stays reachable.

#### Verify IMDSv2 is enforced on every instance behind the resource

```bash
REGION="us-east-1"; INSTANCES="<instance-ids-from-Query-3>"; BAD=0; SEEN=0
for I in $INSTANCES; do
  case "$I" in i-*) ;; *) continue;; esac
  SEEN=$((SEEN+1))
  OUT=$(aws ec2 describe-instances --instance-ids "$I" --region "$REGION" \
          --query 'Reservations[].Instances[].MetadataOptions' --output json 2>&1)
  case "$OUT" in
    *HttpTokens*)
      T=$(printf '%s' "$OUT" | jq -r '.[0].HttpTokens')
      H=$(printf '%s' "$OUT" | jq -r '.[0].HttpPutResponseHopLimit')
      if [ "$T" = "required" ]; then echo "[OK] $I HttpTokens=required hop=$H"
      else echo "[FAIL] $I HttpTokens=$T - still reachable by a forged GET"; BAD=$((BAD+1)); fi;;
    *) echo "[!] INCONCLUSIVE - metadata options unreadable for $I: $OUT"; BAD=$((BAD+1));;
  esac
done
if [ "$SEEN" -eq 0 ]; then
  echo "[!] INCONCLUSIVE - no instance ids were checked. An empty list here is a list that was"
  echo "    never populated, not a fleet that is clean."
elif [ "$BAD" -eq 0 ]; then
  echo "[OK] all $SEEN instance(s) enforce IMDSv2"
else
  echo "[FAIL] $BAD of $SEEN instance(s) do not enforce IMDSv2"
fi
```

`describe-instances` always returns a `MetadataOptions` object, so an empty result means the call
failed rather than that the instance is clean — which is why the empty case is `INCONCLUSIVE` and
counts toward `BAD`.

#### Verify the web ACL is still logging, and that no filter is dropping the evidence

```bash
REGION="us-east-1"; SCOPE="REGIONAL"; ACL_NAME="<web-acl-name>"
ACL_ID=$(aws wafv2 list-web-acls --scope "$SCOPE" --region "$REGION" \
           --query "WebACLs[?Name=='$ACL_NAME'].Id | [0]" --output text 2>&1)
ARN=$(aws wafv2 get-web-acl --name "$ACL_NAME" --scope "$SCOPE" --id "$ACL_ID" \
        --region "$REGION" --query 'WebACL.ARN' --output text 2>&1)
L=$(aws wafv2 get-logging-configuration --resource-arn "$ARN" --scope "$SCOPE" \
      --region "$REGION" --output json 2>&1)
case "$L" in
  *LogDestinationConfigs*)
    D=$(printf '%s' "$L" | jq -r '.LoggingConfiguration.LogDestinationConfigs[0]')
    B=$(printf '%s' "$L" | jq -r '.LoggingConfiguration.LoggingFilter.DefaultBehavior // "KEEP"')
    R=$(printf '%s' "$L" | jq -r '.LoggingConfiguration.RedactedFields | length')
    case "$D" in
      *aws-waf-logs-*) echo "[OK] logging to $D (default behavior $B, $R redacted field(s))";;
      *) echo "[FAIL] destination $D does not carry the required aws-waf-logs- prefix";;
    esac
    [ "$B" = "DROP" ] && echo "[FAIL] the logging filter still defaults to DROP - records are discarded";;
  *WAFNonexistentItemException*)
    echo "[FAIL] $ACL_NAME has NO logging configuration. Every rule above it is blind.";;
  *) echo "[!] INCONCLUSIVE - could not read the logging configuration: $L";;
esac
```

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     a web ACL record whose labels[].name contains"
echo "  core-rule-set:EC2MetaDataSSRF_ and whose action is ALLOW - including the case where the"
echo "  match came from a CAPTCHA rule against a VALID token, which is non-terminating and does"
echo "  reach the application. Any of the four components: _Body, _Cookie, _QueryArguments, _URIPath."
echo "MUST NOT fire on: the same labels with action BLOCK, CAPTCHA or CHALLENGE - those are the"
echo "  separate low-severity stopped stream, not the served one; and it must not fire on a label"
echo "  from another rule group that happens to contain the substring SSRF."
echo "EXPECTED FP, by design: an authorised scanner replaying metadata payloads from a recorded"
echo "  egress address. Exclude by httpRequest.clientIp, never by relaxing the label match."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A metadata SSRF payload was served to the application | The Core rule set was overridden to Count on this web ACL, and no alert existed for the override itself |
| Nobody noticed the attempts that were blocked | Every deployed rule gated on `action:"ALLOW"`, so the stopped stream was discarded and the queue was empty while the control was working |
| One actor probing three components arrived as three unrelated alerts | The observable was split four ways by request component, and nothing joined them on the client address |
| The instance behind the endpoint accepted an IMDSv1 request | `HttpTokens` was `optional`, so a forged plain `GET` could reach the metadata service; the launch template did not set it |
| Nobody could say whether a credential was returned | The metadata fetch produces no AWS telemetry, and the only observable is the credential's use — which requires a trail and a known egress baseline that did not exist |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document).
// Denies launching an instance that does not require IMDSv2, and denies weakening it afterwards.
// StringNotEquals is correct HERE because the compared value is an exact enum, not a wildcarded
// ARN - the *Like operators are needed only where the value contains a *. Getting that backwards
// in a Deny fails closed: Deny + StringEquals on "required" would deny every compliant launch.
{
  "Effect": "Deny",
  "Action": ["ec2:RunInstances"],
  "Resource": "arn:aws:ec2:*:*:instance/*",
  "Condition": {
    "StringNotEquals": { "ec2:MetadataHttpTokens": "required" }
  }
}
```

- **Structural control, and the only one that does not depend on a pattern match: IMDSv2 required,
  fleet-wide, with a hop limit of 1 where the topology allows.** Every WAF rule here matches one
  spelling of one address in one request component. `HttpTokens=required` makes the forged request
  fail regardless of spelling, encoding, component or rule group version, because an SSRF cannot
  issue the `PUT` that mints the token or set the header that carries it.
- **Alert on the override, not only on the traffic.** A `wafv2:UpdateWebACL` that sets
  `OverrideAction: Count` on a managed rule group, or a `RuleActionOverride` to Count on a named
  rule, is the single change that converts a blocking control into a labelling one. It is a
  management event, it is attributable, and in most accounts nothing watches it.
- **Detection improvement: watch the CloudWatch *label* metric alongside the log.** Label metrics
  carry `LabelNamespace` and `Label` dimensions and are emitted independently of the traffic log,
  so a nonzero `EC2MetaDataSSRF_*` label metric with an empty log stream is a precise statement
  that logging is broken, filtered or redacted rather than that traffic is absent — the one signal
  that distinguishes the two silences this playbook keeps warning about.
- **Bound the body-limit evasion.** Keep `SizeRestrictions_BODY` blocking, and on non-ALB resources
  raise `AssociationConfig.RequestBody.DefaultSizeInspectionLimit` toward 64 KB. On an ALB the 8 KB
  limit is fixed, so there the size-restriction rule *is* the control.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1552.005 — Unsecured Credentials: Cloud Instance Metadata API (primary); T1190 — Exploit Public-Facing Application (secondary, the vector) |
| Primary API | None — this is web request telemetry, not an API call. Response uses `wafv2:GetWebACL`, `wafv2:UpdateWebACL`, `wafv2:GetLoggingConfiguration`, `wafv2:UpdateIPSet`, `ec2:ModifyInstanceMetadataOptions` |
| Event source | The **web ACL traffic log** — a separate stream to CloudWatch Logs, S3 or Firehose, destination name prefixed `aws-waf-logs-`, **off by default**, one destination per web ACL. **Not CloudTrail.** WAF's own CloudTrail events are `wafv2.amazonaws.com`, management plane, and CloudFront-scope events land in `us-east-1` |
| Key discriminator | The terminating `action`, read as a verdict — `ALLOW` served, `BLOCK`/`CAPTCHA`/`CHALLENGE` stopped — paired with the count of distinct `EC2MetaDataSSRF_*` component labels per `httpRequest.clientIp` |
| Field shape | `labels` is an array of `{"name": …}`, first 100 only. `httpRequest` nested, `.headers` an array of `{"name","value"}`, **no `.host`**. `terminatingRuleId` is `Default_Action` when nothing terminated. `terminatingRuleMatchDetails` is **empty for these rules** — populated only for SQLi and XSS statements. `oversizeFields` ∈ `REQUEST_BODY`, `REQUEST_JSON_BODY`, `REQUEST_HEADERS`, `REQUEST_COOKIES`. Redacted fields appear as `xxx`, not as absent keys |
| "Was it used" pivot | CloudTrail: an instance-profile session ARN (`assumed-role/<Role>/<instance-id>`) appearing from more than one `sourceIPAddress`, or from outside the fleet's egress set, with `userIdentity.sessionContext.ec2RoleDelivery` of `1.0` for the IMDSv1 path. Owned by `../ec2.credential-access.imds-credential-theft/` |
| Blast radius | Every permission the instance profile grants, usable from the actor's infrastructure and self-renewing while the SSRF primitive survives. The web ACL log bounds nothing: it names a client address and a `httpSourceId`, never the instance or the role |
| Label strings | `awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_Body`, `_Cookie`, `_QueryArguments`, `_URIPath` — exact, case-sensitive, and **not derivable from the rule names** `EC2MetaDataSSRF_BODY`/`_COOKIE`/`_QUERYARGUMENTS`/`_URIPATH` by any transform. The same managed-rules family spells both `SQLi_URIPath` and `SQLiExtendedPatterns_UriPath` |
| Size limits | Body: **8 KB fixed** on ALB and AppSync; 16 KB default, up to 64 KB, elsewhere. Headers and cookies: 8 KB or 200 items, whichever first. Oversize handling on every AWS managed body rule is `Continue`, and the full body is forwarded regardless — applies to `_Body` only |
| Error strings | Response-path calls: `WAFNonexistentItemException` (400, **not 404** — this is what "no logging configuration" looks like), `WAFOptimisticLockException` (400, a stale `LockToken`), `WAFInvalidParameterException` (400), `WAFLimitsExceededException` (400), `WAFLogDestinationPermissionIssueException` (400), `WAFServiceLinkedRoleErrorException` (400), `WAFInternalErrorException` (500) |

**MITRE mapping note.** The source labels three of the four rules `T1552.005 / TA0006` and the Body
rule the bare parent `T1552 / TA0006` — an inconsistency inside one set of four siblings. T1552.005
is retained as primary for all four: the objective is the cloud instance metadata API and nothing
else. **T1190** is added and is not in the source; what the web ACL observes is an attempt against a
public-facing application, and a mapping that carries only Credential Access loses the tactic under
which the alert actually arrives. Both verified live 2026-08-29.

### Residual Risk

The rule group is blocking again, the address is blocked, IMDSv2 is enforced and the sessions are
revoked, and none of that answers the question the incident was opened on: **whether a credential
was returned.** The metadata fetch produces no AWS telemetry, and the only evidence is the
credential's later use — so in an account without a baseline of the fleet's egress addresses, "was
it taken" closes as unknown and credential rotation for everything the instance profile could reach
is the only remediation that does not depend on evidence you do not have.

Three things stay open after every step above. The **application is still an SSRF** until the
allowlist ships: the WAF rule matches one spelling of one address, and a DNS name resolving to
`169.254.169.254`, an open redirect, or an alternate encoding walks past it with no label at all.
The **body path on an ALB is still 8 KB deep** and cannot be made deeper, so a padded body remains
uninspected and forwarded whatever else is fixed. And the **override can come back**: if the Count
override lives in IaC, §3 Step 1 is undone by the next deploy, and the only warning will be the
absence of alerts — which is the same thing this control looks like when it is working perfectly.
