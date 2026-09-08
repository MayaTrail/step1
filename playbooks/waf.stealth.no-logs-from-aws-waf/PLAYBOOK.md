# IR Playbook: WAF Logging Stopped — `DeleteLoggingConfiguration`, so the web ACL still blocks and records nothing

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment (a web ACL's request logging is stopped; evaluation and blocking continue, evidence does not) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High.** Nothing is exposed by this act — WAF keeps evaluating and blocking — but everything done afterwards is unobservable, and the gap is permanently unrecoverable. Its value to an attacker is entirely in what follows it, which makes response urgency a function of elapsed time rather than of the call itself |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685.002 |
| Services in Scope | WAF, CloudWatch Logs / S3 / Firehose (the destination), CloudTrail, IAM |

**What the technique does:** WAF request logging is enabled per web ACL by
`wafv2:PutLoggingConfiguration` and by nothing else — there is no account-level or
organisation-level default. Three calls stop it. `DeleteLoggingConfiguration` removes the
configuration outright. `PutLoggingConfiguration` **completely replaces** the existing
configuration, so it installs a `LoggingFilter` of `DefaultBehavior: DROP` that discards
every record while `GetLoggingConfiguration` still returns a configuration and the console
still shows logging as enabled. And removing the delivery permission — the log-group
resource policy, the S3 bucket policy, or the Firehose service-linked role — stops delivery
without touching WAF at all. In every case the web ACL continues to evaluate rules and block
requests; only the record stops.

**Detection thesis.** The signal is the **control-plane call**, not the silence. An absence
alert on the traffic stream cannot distinguish the three malicious causes from the fourth
and commonest one — genuinely no traffic — and its input is precisely what the attacker
removed. The source rule is exactly that absence alert.

---

## 1. Preparation

**Logging & Visibility**
- CloudTrail management events for `wafv2.amazonaws.com`, specifically
  `PutLoggingConfiguration` and `DeleteLoggingConfiguration`. **These survive the WAF stream
  stopping and are the only reliable signal**
- CloudTrail for the delivery-side calls — `DeleteLogDelivery`, `DeleteResourcePolicy`,
  `DeleteBucketPolicy` — scoped by the `aws-waf-logs-` destination prefix
- **A recorded baseline of every web ACL's logging configuration**: destination ARN, any
  `LoggingFilter`, any `RedactedFields`. `PutLoggingConfiguration` is a full replacement, so
  after a change there is nothing to compare against unless it was captured beforehand
- `VisibilityConfig.CloudWatchMetricsEnabled` and `SampledRequestsEnabled` on every web ACL
  and rule — both are **independent of logging** and are what survive it
- Know the destination naming constraint: it **must begin `aws-waf-logs-`**, must be in the
  same Region and account, and there is **one destination per web ACL** — no second copy

**Alerting (must be pre-configured)**
- **`wafv2:DeleteLoggingConfiguration` succeeding on any web ACL → P0**
- **`wafv2:PutLoggingConfiguration` installing a `LoggingFilter` with `DefaultBehavior: DROP` and no keeping filter → P0**
- **`wafv2:PutLoggingConfiguration` installing any `DROP` default, or adding `RedactedFields` → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- Which principals and automation roles touch this service at all. In most estates the list is short, which makes an unfamiliar caller a finding before any threshold is evaluated.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `DeleteLoggingConfiguration` succeeding | CloudTrail (management) | T1685.002 |
| P0 | `PutLoggingConfiguration` whose `loggingFilter.DefaultBehavior` is `DROP` with an empty `Filters` array | CloudTrail (management) | T1685.002 |
| P1 | `PutLoggingConfiguration` installing any `DROP` default, or adding `RedactedFields` | CloudTrail (management) | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `DeleteLogDelivery` / `DeleteResourcePolicy` / `DeleteBucketPolicy` naming an `aws-waf-logs-` destination | CloudTrail (management) | T1685.002 |
| P3 | No WAF records in a window — corroborating only; four causes produce it | WAF traffic log | T1685.002 |

### Detection Rule Quality Notes

The source rule watches the stream that the technique removes, and cannot say why it stopped.

| Issue | Impact | Correction |
|-------|--------|-----------|
| It is an absence alert on the WAF traffic stream | Its input is exactly what the attacker deleted. Worse, four causes produce silence and only three are incidents — the fourth, **genuinely no traffic**, is routine for any dev or low-volume endpoint, so the alert is noisy where it is not blind | Detect the **control-plane calls** that produce silence. They are CloudTrail management events and they survive. Keep the absence alert as corroboration at P3 |
| It cannot see a `LoggingFilter` of `DefaultBehavior: DROP` | The stream goes silent while `GetLoggingConfiguration` returns a configuration and the console reports logging as enabled. Any check that asks "is logging configured" answers yes | A rule on `PutLoggingConfiguration` that reads the resulting `loggingFilter`, treating `DROP` with no keeping filter as P0 |
| It cannot see the delivery permission being removed | The log-group resource policy, bucket policy or service-linked role is what actually carries the records. Removing it stops delivery with **WAF's own configuration untouched and correct** | A rule on the delivery-side deletions, scoped by the mandatory `aws-waf-logs-` prefix |
| No handling of the repair-destroys-evidence ordering | The only way to restore logging is `PutLoggingConfiguration`, which is a full replacement — so repairing overwrites the DROP filter or redaction that is the evidence | §3 captures the current configuration before repairing it |

**Recommended detection — the logging configuration deleted outright.**

```yaml
# WAF Logging Stopped (T1685.002 — Disable or Modify Cloud Log)
#
# The source rule is an absence alert: no WAF log records in a window. Absence alerts have a
# structural problem this playbook exists to confront — the detection depends on the
# telemetry the technique disables, so the alert's own input is what was removed. It cannot
# tell you WHY the stream stopped, and there are four distinct causes with four different
# responses, only one of which is an incident.
#
# The rules below invert the problem: instead of watching the traffic stream for silence,
# watch the CONTROL PLANE for the calls that produce silence. Those are CloudTrail
# management events and they survive the WAF log stopping.
#
# Two of the four causes leave the logging configuration in place and still stop delivery,
# which is why a rule on DeleteLoggingConfiguration alone is insufficient:
#   * A LoggingFilter with DefaultBehavior DROP and no keeping filter silences the stream
#     while GetLoggingConfiguration still returns a configuration and the console still
#     shows logging enabled.
#   * PutLoggingConfiguration COMPLETELY REPLACES the previous configuration, so a call that
#     "fixes" logging also destroys the record of what it used to be.
title: WAF logging configuration deleted
id: 5b8f2e14-9c47-4a03-b6d1-3e07f5a82c94
name: waf_logging_config_deleted
status: experimental
description: >-
  wafv2:DeleteLoggingConfiguration removed a web ACL's logging configuration. WAF continues
  to evaluate and block; it stops writing any request record, and the gap is unrecoverable.
references:
  - https://attack.mitre.org/techniques/T1685/002/                             # retrieved 2026-08-30
  - https://docs.aws.amazon.com/waf/latest/developerguide/logging-management-configure.html  # retrieved 2026-08-30
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'wafv2.amazonaws.com'
    eventName: 'DeleteLoggingConfiguration'
  success:
    errorCode: null
  condition: selection and success
falsepositives:
  - Decommissioning a web ACL. The delete should be accompanied by the ACL's own deletion
    within minutes; a delete that stands alone is the finding.
level: high
---
# The quiet variant, and the reason an absence alert cannot be replaced by watching Delete
# alone. PutLoggingConfiguration is a full replacement, so it is used both to enable logging
# and to silence it — a LoggingFilter of DefaultBehavior DROP leaves the configuration
# present and the console reporting logging as enabled, with nothing delivered.
title: WAF logging configuration replaced
id: 2d94a7f6-08be-4c51-9f37-6ac1b2e08d5f
name: waf_logging_config_replaced
status: experimental
description: >-
  wafv2:PutLoggingConfiguration replaced a web ACL's logging configuration. This both
  enables logging and is the only way to install a DROP filter or redact fields, so every
  call needs the resulting configuration read before it is dispositioned.
references:
  - https://docs.aws.amazon.com/waf/latest/developerguide/logging-management-configure.html  # retrieved 2026-08-30
  - https://docs.aws.amazon.com/waf/latest/APIReference/API_LoggingFilter.html  # retrieved 2026-08-30
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'wafv2.amazonaws.com'
    eventName: 'PutLoggingConfiguration'
  success:
    errorCode: null
  condition: selection and success
falsepositives:
  - Enabling logging for the first time, or moving the destination. Both are legitimate and
    both use this call — read the resulting LoggingFilter before dispositioning. This rule
    is deliberately broad because the call is the only signal; the content decides.
level: medium
---
# The delivery-side break, which touches no WAF API at all. Enabling logging creates a
# resource policy on the CloudWatch Logs group, a bucket policy on S3, or a service-linked
# role for Firehose. Removing that permission out from under a live configuration stops
# delivery while GetLoggingConfiguration still returns an intact, correct configuration.
title: WAF log delivery permission removed
id: e7c035a9-1f62-4d88-a094-5b3e7c216fda
status: experimental
description: >-
  A log-delivery permission underpinning a WAF logging configuration was removed. WAF's own
  configuration is untouched and still reports as enabled; delivery stops silently.
references:
  - https://docs.aws.amazon.com/waf/latest/developerguide/logging-destinations.html  # retrieved 2026-08-30
tags:
  - attack.defense-impairment
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName:
      - 'DeleteLogDelivery'
      - 'DeleteResourcePolicy'
      - 'DeleteBucketPolicy'
  # The destination name must begin with aws-waf-logs- for WAF to accept it, so this prefix
  # is a reliable way to scope the noisy generic calls to WAF's own destinations.
  waf_destination:
    requestParameters|contains: 'aws-waf-logs-'
  success:
    errorCode: null
  condition: selection and waf_destination and success
falsepositives:
  - Log-group lifecycle managed by IaC. Correlate against the same principal's other calls
    in the window; a deletion with no accompanying recreation is the finding.
level: medium
```

Reproduced byte-for-byte from the first rule document of
`detections/sigma_t1685_002.yml`. Two further documents ship in that file: configuration
replaced (`medium`, deliberately broad because the resulting content decides), and delivery
permission removed (`medium`). **Deploy the file, not this excerpt.**

**What these rules structurally cannot do.** They fire on the call, not on the effect — so
they cannot tell you whether records were actually lost, only that the mechanism to lose
them was invoked. And they cannot recover anything: for any window without a logging
configuration there is no request record and never will be. Full reasoning in
`detections/detection_note_t1685_002.md`.

---

### Key Investigation Queries

> These run against **CloudTrail**, deliberately — the WAF traffic log is what the technique removes. WAF is regional; run in the web ACL's Region, and use `CLOUDFRONT` scope with `us-east-1` for a CloudFront web ACL.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: who changed logging, on which web ACL, and to what

```bash
REGION="us-east-1"

for EV in PutLoggingConfiguration DeleteLoggingConfiguration; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "wafv2.amazonaws.com") |
    (.userIdentity.arn // "") as $arn | ($arn | split("/")) as $p |
    # assumed-role ARN: role name is the 2nd "/" segment, the LAST is the SESSION name.
    {time: .eventTime,
     event: .eventName,
     caller_arn: $arn,
     caller: (if ($arn | test(":assumed-role/")) then $p[1] else $p[-1] end),
     access_key: .userIdentity.accessKeyId,
     web_acl: (.requestParameters.loggingConfiguration.resourceArn
               // .requestParameters.resourceArn),
     destinations: (.requestParameters.loggingConfiguration.logDestinationConfigs // []),
     filter_default: (.requestParameters.loggingConfiguration.loggingFilter.DefaultBehavior // "none"),
     filter_count: ((.requestParameters.loggingConfiguration.loggingFilter.Filters // []) | length),
     redacted: ((.requestParameters.loggingConfiguration.redactedFields // []) | length),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

A `DeleteLoggingConfiguration` with `error: "SUCCESS"` is the unambiguous case. On a
`PutLoggingConfiguration`, read `filter_default` and `filter_count` together: **`DROP` with
`filter_count: 0` discards every record** while the configuration reads as present.
`filter_default: "DROP"` with filters present means only what those filters explicitly keep
survives — read them. A non-zero `redacted` means those components will log as the literal
string `xxx`. Record `caller_arn`, `access_key`, `web_acl` and the `time`; the window from
that timestamp to now is the gap.

#### Query 2 — Capture what survives, before it expires

The three-hour sampling window is the only evidence with a clock on it. Take it first.

```bash
REGION="us-east-1"; NAME="<web-acl-name>"; ID="<web-acl-id>"; SCOPE="REGIONAL"
GAP_START="<time-from-Query-1>"                 # ISO8601, when logging stopped

# GetSampledRequests: a random sample from the first 5,000 requests in the chosen window,
# and the window may only be within the PREVIOUS THREE HOURS. No query string, no body.
aws wafv2 get-sampled-requests \
  --web-acl-arn "<web_acl-from-Query-1>" --rule-metric-name "ALL" --scope "$SCOPE" \
  --time-window StartTime="$(date -u -d '3 hours ago' +%Y-%m-%dT%H:%M:%SZ)",EndTime="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --max-items 500 --region "$REGION" --output json > /tmp/waf-sample.json 2>/dev/null

if [ ! -s /tmp/waf-sample.json ]; then
  echo "[!] get-sampled-requests returned nothing — the ACL may have had no traffic, or"
  echo "    SampledRequestsEnabled is off, or the principal lacks wafv2:GetSampledRequests."
  echo "    INCONCLUSIVE, not clean."
else
  echo "[OK] Captured $(jq '.SampledRequests | length' /tmp/waf-sample.json) sampled requests to /tmp/waf-sample.json"
  echo "[i] This covers at most the last three hours. Anything before that is gone."
fi

# Metrics survive logging and are independent of it — counts only, no request content.
aws cloudwatch get-metric-statistics --namespace AWS/WAFV2 --metric-name BlockedRequests \
  --dimensions Name=WebACL,Value="$NAME" Name=Rule,Value=ALL Name=Region,Value="$REGION" \
  --start-time "$GAP_START" --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 300 --statistics Sum --region "$REGION" --output json \
  | jq '{datapoints: (.Datapoints | length), blocked: ([.Datapoints[].Sum] | add // 0)}'
```

The sample is the only request-level evidence for the gap, and only for its last three
hours. The metric tells you how much traffic the gap covered and how it was actioned — that
is the size of what is unrecoverable, and it belongs in the incident record.

#### Query 3 — Sweep: the same condition everywhere else in the account

```bash
REGION="us-east-1"
EVENTS="DeleteBucketPolicy DeleteLogDelivery DeleteResourcePolicy"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in $EVENTS; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "wafv2.amazonaws.com") |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'group_by(.caller) | map({caller: .[0].caller, calls: length,
                                       events: (map(.event) | unique),
                                       keys: (map(.access_key) | unique),
                                       first: (map(.time) | min), last: (map(.time) | max)})
             | sort_by(-.calls)'
```

The alerting event named one resource; this asks whether the same principal did the same thing
elsewhere, and whether anyone else did it too. Group by caller rather than by resource: the
question the eradication phase needs answered is *how much of this is one actor's work*, and a
per-resource list cannot say. `access_key` is emitted here because the next query consumes it.

This is a **management-event** query. Any data-plane call in this technique returns zero from
`lookup-events` regardless of whether it happened — see the caveat in the preamble.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-3>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique),
                               errors: (map(.error) | unique),
                               ips: (map(.ip) | unique | .[0:5])})'
```

Keyed on the access key rather than the ARN, because one credential is used across many
sessions and the key is what identifies the credential. The per-service grouping answers the
question this playbook cannot: whether this technique was the objective or one stop on a tour.
A service in that list with no business reason to appear is the next thread to pull.

**`AttributeKey=Username` would not work here.** For a role session it matches the SESSION name,
which for an instance-profile session is the instance ID — so a role-name lookup returns zero.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**Capture before you repair.** The only way to restore logging is
`PutLoggingConfiguration`, and that call is a full replacement — so repairing it overwrites
the DROP filter or the redaction that is the evidence of how it was broken.

> Run under the **break-glass responder credentials** from §1, not under the principal that
> made the change.

#### Step 1 — Capture the current configuration, then restore logging

```bash
REGION="us-east-1"
WEB_ACL_ARN="<web_acl-from-Query-1>"
EVIDENCE="/tmp/ir-waf-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$EVIDENCE"

CFG=$(aws wafv2 get-logging-configuration --resource-arn "$WEB_ACL_ARN" \
        --region "$REGION" --output json 2>/dev/null)
if [ -z "$CFG" ]; then
  echo "[i] No logging configuration present — consistent with DeleteLoggingConfiguration."
  echo "    Nothing to capture; the Query 1 event is the record of what it was."
else
  printf '%s' "$CFG" > "$EVIDENCE/logging-config-before.json"
  echo "[OK] Captured current configuration to $EVIDENCE/logging-config-before.json"
  printf '%s' "$CFG" | jq -r '{default: (.LoggingConfiguration.LoggingFilter.DefaultBehavior // "none"),
                               filters: ((.LoggingConfiguration.LoggingFilter.Filters // []) | length),
                               redacted: ((.LoggingConfiguration.RedactedFields // []) | length),
                               destinations: .LoggingConfiguration.LogDestinationConfigs}'
fi

echo "[i] Restore with put-logging-configuration using the BASELINE from §1 — the destination"
echo "    ARN must begin aws-waf-logs-, be in this Region and account, and there is exactly"
echo "    ONE destination per web ACL. This call REPLACES whatever is there now."
```

#### Step 2 — Contain the principal

```bash
SUSPECT_ARN="<caller_arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["wafv2:DeleteLoggingConfiguration","wafv2:PutLoggingConfiguration","wafv2:UpdateWebACL"],"Resource":"*"}]}'

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')       # user ARN: name = LAST segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive \
      && echo "[OK] Disabled key $K for $U"
  done
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyWafLogging" \
    --policy-document "$DENY" && echo "[OK] Denied further WAF logging changes by user $U"
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')        # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyWafLogging" \
    --policy-document "$DENY" && echo "[OK] Denied further WAF logging changes by role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

---

## 4. Eradication

### Remove Attacker Access

- **Treat the gap as an investigation, not a closed item.** Reconstruct what the principal
  did during it from CloudTrail — logging off in WAF does not stop CloudTrail — using the
  `access_key` from Query 1
- **Check every other web ACL** for the same change. Someone silencing one rarely stops
  there, and the account may have several
- **Verify the destination itself is intact** — resource policy on the log group, bucket
  policy on S3, service-linked role for Firehose. A repaired WAF configuration pointing at a
  destination it can no longer write to is silently still broken
- **Right-size the permission.** `wafv2:DeleteLoggingConfiguration` and
  `wafv2:PutLoggingConfiguration` belong to the security-tooling pipeline, not to
  application teams
- **Remove the emergency deny policy** once the configuration is verified

---

## 5. Recovery

### Restore Clean State

#### Verify logging is genuinely delivering, not merely configured

```bash
REGION="us-east-1"; WEB_ACL_ARN="<web_acl-from-Query-1>"

CFG=$(aws wafv2 get-logging-configuration --resource-arn "$WEB_ACL_ARN" \
        --region "$REGION" --output json 2>/dev/null)
if [ -z "$CFG" ]; then
  echo "[FAIL] No logging configuration on $WEB_ACL_ARN"
else
  DEF=$(printf '%s' "$CFG" | jq -r '.LoggingConfiguration.LoggingFilter.DefaultBehavior // "none"')
  KEEP=$(printf '%s' "$CFG" | jq '(.LoggingConfiguration.LoggingFilter.Filters // []) | length')
  DEST=$(printf '%s' "$CFG" | jq -r '.LoggingConfiguration.LogDestinationConfigs[0] // ""')
  if [ "$DEF" = "DROP" ] && [ "${KEEP:-0}" -eq 0 ]; then
    echo "[FAIL] Configuration present but LoggingFilter DROPs everything — still silent"
  elif [ -z "$DEST" ]; then
    echo "[FAIL] Configuration present with no destination"
  else
    echo "[OK] Logging configured to $DEST (DefaultBehavior=$DEF, $KEEP filter(s))"
  fi
fi
```

> A configuration reading as present is **not** proof of delivery. Confirm records are
> actually arriving at the destination before closing — a correct configuration pointing at
> a log group whose resource policy was removed produces exactly this output and no records.

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     eventSource wafv2.amazonaws.com, eventName DeleteLoggingConfiguration,"
echo "                  errorCode absent -> waf_logging_config_deleted, level high"
echo "MUST fire on:     PutLoggingConfiguration whose loggingFilter.DefaultBehavior is DROP"
echo "                  with an empty Filters array -> P0 by the KQL verdict"
echo "MUST NOT fire on: a failed call (errorCode present) — the success filter excludes it"
echo "EXPECTED, by design: a legitimate first-time enablement also fires the replace rule at"
echo "                  medium. That is intended — the call is the only signal and the"
echo "                  resulting configuration decides. Do NOT filter it out."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A web ACL stopped recording requests while continuing to block them | `wafv2:DeleteLoggingConfiguration` / `PutLoggingConfiguration` available outside the security-tooling pipeline |
| The change was not detected as it happened | The deployed rule watched the traffic stream for absence — the same stream the change removed — and could not separate it from a quiet endpoint |
| A DROP filter would have been invisible | No check read the resulting `LoggingFilter`; `GetLoggingConfiguration` and the console both report such a web ACL as logging enabled |
| The gap is unrecoverable | Only one logging destination exists per web ACL and no second copy is possible; nothing reconstructs the records |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Both calls, not just the delete: PutLoggingConfiguration is a full replacement and is
// therefore also the silence call.
{
  "Effect": "Deny",
  "Action": ["wafv2:DeleteLoggingConfiguration", "wafv2:PutLoggingConfiguration"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/security-tooling" }
  }
}
```

> The condition value carries a wildcard, so it needs `ArnNotLike`. Under `StringNotEquals`
> the wildcard is not expanded, the condition matches every request, and the `Deny` denies
> everything — an outage rather than a bypass.

- **Baseline every web ACL's logging configuration and reconcile it on a schedule.**
  `PutLoggingConfiguration` is a full replacement, so a stored baseline is the only way to
  know what changed
- **Enable `SampledRequestsEnabled` and `CloudWatchMetricsEnabled` everywhere.** Both are
  independent of logging and are all that survives it — and the sample expires in three hours
- **Consider Amazon Security Lake** as a second path. It is configured outside the WAF
  logging configuration, so the calls above do not disable it

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log |
| MITRE tactic | Defense Impairment (TA0112). |
| Primary API | `wafv2:DeleteLoggingConfiguration` · `wafv2:PutLoggingConfiguration` (a **full replacement**) · delivery-side `DeleteLogDelivery` / `DeleteResourcePolicy` / `DeleteBucketPolicy` |
| Event source | `wafv2.amazonaws.com`, CloudTrail **management** — this survives the WAF traffic log stopping, which is why detection lives here |
| Key discriminator | The control-plane call and the **resulting configuration** — `DefaultBehavior: DROP` with no keeping filter, or a removed destination permission. Not the silence |
| Silent variants | A `LoggingFilter` DROP leaves `GetLoggingConfiguration` and the console reporting logging as **enabled**. `RedactedFields` logs those components as the literal string `xxx`, not as absent keys. Neither appears in a web-ACL rule diff |
| What survives | CloudWatch `AWS/WAFV2` metrics (counts only) · `GetSampledRequests` (**previous 3 hours only**, ≤500 items, **no query string, no body**) · Security Lake if separately configured |
| Constraints | Destination name **must begin `aws-waf-logs-`** · same Region and account · **one destination per web ACL** |
| Blast radius | Nothing is exposed by the act itself. Everything done afterwards is unobservable, and proportional to elapsed time |

### Residual Risk

**The gap is permanent.** For any window in which the web ACL had no working logging
configuration there is no per-request record and never will be. `GetSampledRequests` covers
at most the last three hours and carries no query string and no body; metrics give counts
without content. Whatever passed through is knowable only in aggregate, and only if
`SampledRequestsEnabled` and `CloudWatchMetricsEnabled` were on.

**Repairing logging destroyed part of the evidence, by design.** The only restore path is a
full replacement, so unless §3 Step 1 captured the DROP filter or the redaction first, how
the silence was produced is now only inferable from the CloudTrail request parameters.

**A correct-looking configuration is not proof of delivery.** If the destination's resource
policy, bucket policy or service-linked role is still missing, `GetLoggingConfiguration`
returns an intact configuration and no records arrive. Verify at the destination.

**There is no second copy.** One logging destination per web ACL, no fan-out. Any
redundancy has to be built outside WAF — Security Lake, or a subscription filter on the
destination log group — and neither is enabled by the calls this playbook restores.
