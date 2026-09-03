# IR Playbook: SQL Injection in Request Body — `SQLi_Body` served to the application because the WAF was set not to stop it

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Exploitation of a public-facing application (an SQL-injection body reached the backend with WAF matching but not blocking) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High.** The alert fires only when the request was *allowed*, and because these rules default to Block, an allow means the rule group was overridden to Count or the rule excluded. So every firing is two findings at once: an injection attempt reached the application, **and** the control that should have stopped it is switched off. The source rule rates this P2 behind a four-in-five-minutes threshold; one is an incident |
| MITRE Tactics | Initial Access |
| MITRE Techniques | T1190 |
| Services in Scope | WAF, the protected resource (ALB / CloudFront / API Gateway / AppSync), the application's database, CloudTrail (for the configuration change), IAM |

**What the technique does:** a request arrives carrying SQL syntax in its body. AWS WAF evaluates it
against `AWSManagedRulesSQLiRuleSet`, the `SQLi_BODY` or `SQLiExtendedPatterns_BODY` rule
matches, and WAF attaches the label `awswaf:managed:aws:sql-database:SQLi_Body` (or
`…:SQLiExtendedPatterns_Body`). Every rule in that group has a default action of **Block**
— so in a correctly configured web ACL the request stops there. When the log instead shows
`action: "ALLOW"` next to that label, the request was served to the backend, and only two
configurations produce that: the rule group carries `OverrideAction: Count`, or the
specific rule was excluded. The body itself is never recorded, so what the application
actually received has to come from the application.

**Detection thesis.** The signal is the **label together with the terminating action**, and
the action is a verdict axis rather than a filter — matched-and-allowed is a control
failure, matched-and-blocked is a targeting signal. The source rule gates on
`action:"ALLOW"` alone, which makes it silent in every web ACL where the protection is
working and raises nothing at all when an attempt is blocked.

---

## 1. Preparation

**Logging & Visibility**
- **WAF traffic logs are not CloudTrail and are off by default.** They are enabled per web
  ACL by `wafv2:PutLoggingConfiguration` and by nothing else; there is no account-level or
  organisation-level default. Without it, WAF still evaluates and blocks — and writes no
  request record anywhere, ever
- The destination name must begin with `aws-waf-logs-`, must be in the same Region and
  account as the web ACL, and there is **one destination per web ACL** — no fan-out
- Record fields this playbook reads: `action`, `labels[].name` (an array of **single-key
  objects**, not strings), `httpRequest.clientIp`, `.uri`, `.args`, `.country`,
  `.headers[]` (an array of `{name,value}` — **there is no `httpRequest.host`**),
  `oversizeFields`, `webaclId` (which holds the web ACL **ARN**), `httpSourceName`
- **`AWSManagedRulesSQLiRuleSet` must be associated with the web ACL.** It is use-case
  specific and is *not* part of a baseline deployment; if it is absent, every rule here is
  silent for a configuration reason
- CloudTrail management events for `wafv2:UpdateWebACL` and `wafv2:PutLoggingConfiguration`
  — the configuration change that produced the `ALLOW` is visible only there

**Alerting (must be pre-configured)**
- **SQLi body label with `action: ALLOW` → P0**
- **SQLi body label with `action: ALLOW` and `oversizeFields` naming the body → P0**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- CloudWatch Logs Insights access for the log group named in **Logging & Visibility**, and the patience for `start-query` to settle before reading results.
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
| P0 | `SQLi_Body` / `SQLiExtendedPatterns_Body` label with `action: ALLOW` | WAF traffic log | T1190 |
| P0 | The same, with `oversizeFields` containing `REQUEST_BODY` — the rule saw only part of what the application received | WAF traffic log | T1190 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Twenty or more **blocked** SQLi bodies from one client against one host in 10 minutes | WAF traffic log | T1190 |
| P3 | A single blocked SQLi body — the control working | WAF traffic log | T1190 |

### Detection Rule Quality Notes

The source rule fires only in the configuration where the protection is disabled, and is
silent in the configuration where it is working.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Gates on `action:"ALLOW"` | Every rule in `AWSManagedRulesSQLiRuleSet` defaults to **Block**, so the rule is silent in every correctly configured web ACL — and a blocked attempt raises nothing at all, leaving the attacker invisible exactly when the control works | Make the terminating action a **verdict axis**: match the label, emit the action, `ALLOW` at P0 and `BLOCK` as a volume signal |
| Threshold of 4 in 5 minutes on that same allowed stream | An allowed SQLi body means the rule group is overridden to Count or the rule excluded. That is not a signal needing a volume floor — one is an incident | Threshold removed from the allow path; the volume rule counts **blocked** attempts, where a floor is meaningful |
| `CAPTCHA` and `CHALLENGE` are not considered | Both are **terminating** actions when the request carries no valid token, so the request did **not** reach the application. Counting them as neither allow nor block leaves them unhandled | Grouped with `BLOCK` as "stopped"; noted that a CAPTCHA match against a *valid* token yields a top-level `ALLOW` and did reach the backend |
| No handling of the body inspection limit | Body inspection stops at 8 KB on ALB and AppSync (fixed) and 16 KB elsewhere, every managed body rule uses `Continue`, and AWS forwards the **entire** body regardless. Padding past the limit defeats the rule and the alert never fires | An `informational` rule on `oversizeFields` + `ALLOW`, shipped as the context that explains an absence |
| Matches the label by regex substring | Workable here, but fragile as a habit: the same rule group emits `SQLi_URIPath` and `SQLiExtendedPatterns_UriPath`, so any casing transform returns zero for one of them | `\|endswith` on the exact documented label tails, both spellings enumerated |

**Recommended detection — SQLi matched in a request body and allowed to the application.**

```yaml
# SQL Injection Detected in Request Body (T1190)
#
# The source rule is `action:"ALLOW" AND labels ~ SQLi_Body|SQLiExtendedPatterns_Body`,
# thresholded at 4 in 5 minutes. Three defects, in descending order of consequence.
#
# 1. THE ALLOW GATE INVERTS THE ALERT. Every rule in AWSManagedRulesSQLiRuleSet has a
#    default action of Block. In a web ACL running that group at its defaults the rule is
#    SILENT, and a blocked injection attempt raises nothing at all — the attacker is
#    invisible exactly when the control is working. An ALLOW alongside an SQLi label means
#    the rule group was overridden to Count or the rule was excluded: the finding is that
#    THE PROTECTION IS OFF, which is not what the rule's title says.
# 2. THE VOLUME THRESHOLD COMPOUNDS IT. Four allowed injections in five minutes is not a
#    tuning floor for a signal that already means the control is disabled; one is an
#    incident.
# 3. THE BODY LIMIT IS AN EVASION PATH THE RULE CANNOT SEE. Body inspection stops at 8 KB
#    on ALB and AppSync (fixed, not adjustable) and 16 KB by default elsewhere. Every AWS
#    managed body rule uses oversize handling Continue, and AWS forwards the ENTIRE body to
#    the application regardless. Padding past the limit defeats the rule while the log
#    records oversizeFields REQUEST_BODY and no body rule match.
#
# The label casing here is correct in the source and is preserved: SQLi_Body and
# SQLiExtendedPatterns_Body. Do not "normalise" it — the same rule group ships
# SQLi_URIPath and SQLiExtendedPatterns_UriPath, which differ from each other.
title: SQL injection matched in request body and allowed to the application
id: 4e32bc9b-f7fd-4053-85ae-bcb15c59a0c0
name: waf_sqli_body_allowed
status: experimental
description: >-
  AWS WAF matched an SQL-injection pattern in a request body and the request was still
  served to the backend. Because these rules default to Block, an ALLOW means the rule
  group was overridden to Count or the rule excluded — the protection is off.
references:
  - https://attack.mitre.org/techniques/T1190/                                # retrieved 2026-08-30
  - https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-use-case.html  # retrieved 2026-08-30
tags:
  - attack.initial-access
  - attack.t1190
logsource:
  product: aws
  service: waf
detection:
  # labels is an array of single-key objects: [{"name": "..."}]. The path is labels.name,
  # not a bare string array — a flat match on `labels` returns nothing.
  sqli_body_label:
    labels.name|endswith:
      - ':SQLi_Body'
      - ':SQLiExtendedPatterns_Body'
  reached_backend:
    action: 'ALLOW'
  condition: sqli_body_label and reached_backend
falsepositives:
  - An application that legitimately accepts SQL text in a body field — a query builder, an
    admin console, a BI tool. Allowlist by URI path, never by source IP.
  - A deliberate Count-mode evaluation of a newly added rule group. That is the same
    condition this rule detects; confirm it is intentional and time-boxed.
level: high
---
# The same match, blocked. Not the same incident: this is the control working, and it is
# the volume signal the source rule has no way to express because its ALLOW gate discards
# every one of these events.
title: SQL injection matched in request body and blocked
id: 3726bcd3-fd69-4e82-ad8b-478aaa4c8e7a
name: waf_sqli_body_blocked
status: experimental
description: Base rule — volume component only, not for direct alerting.
references:
  - https://attack.mitre.org/techniques/T1190/                                # retrieved 2026-08-30
tags:
  - attack.initial-access
  - attack.t1190
logsource:
  product: aws
  service: waf
detection:
  sqli_body_label:
    labels.name|endswith:
      - ':SQLi_Body'
      - ':SQLiExtendedPatterns_Body'
  stopped:
    action:
      - 'BLOCK'
      - 'CAPTCHA'
      - 'CHALLENGE'
  condition: sqli_body_label and stopped
level: low
---
# Threshold basis, stated rather than invented: this counts BLOCKED attempts, so it is a
# targeting signal, not a compromise signal. A single scanner sweep trivially exceeds any
# small number, so the value is set where sustained hand-driven probing of one client
# against one host becomes distinguishable from a drive-by. Baseline against your own edge
# before deploying; a public site will need it higher.
title: Sustained SQL injection attempts against one host from one client
id: 8182b333-f4ef-4054-94b8-726acdd6b96d
status: experimental
description: >-
  One client sent twenty or more blocked SQL-injection request bodies to a single host in
  ten minutes — targeted probing rather than background scanning.
references:
  - https://attack.mitre.org/techniques/T1190/                                # retrieved 2026-08-30
tags:
  - attack.initial-access
  - attack.t1190
correlation:
  type: event_count
  rules:
    - waf_sqli_body_blocked
  group-by:
    - httpRequest.clientIp
    - webaclId
  timespan: 10m
  condition:
    gt: 19
level: medium
---
# The evasion the body rules structurally cannot catch, made visible. oversizeFields is
# populated by WAF itself when a component exceeded the inspection limit; if the body was
# oversize AND no body rule matched, the tail of that body was never inspected and was
# still forwarded to the application. This does not prove an attack — it proves the body
# rules did not see the whole request.
title: Request body exceeded the WAF inspection limit and was forwarded uninspected
id: 39d92190-b7fe-4bb3-ac5a-e52545eb2632
status: experimental
description: >-
  A request body was larger than AWS WAF could inspect, so the portion beyond the limit
  reached the application unexamined. Read alongside any body-rule finding, and as the
  blind spot behind their absence.
references:
  - https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html  # retrieved 2026-08-30
tags:
  - attack.initial-access
  - attack.t1190
  - attack.defense-impairment
logsource:
  product: aws
  service: waf
detection:
  oversize_body:
    oversizeFields|contains:
      - 'REQUEST_BODY'
      - 'REQUEST_JSON_BODY'
  reached_backend:
    action: 'ALLOW'
  condition: oversize_body and reached_backend
falsepositives:
  - Any application that legitimately accepts large uploads. This is expected traffic on
    such a path; the rule earns its place as context for a body-rule finding, not as a
    standalone alert. Scope it to paths that should never receive a large body.
level: informational
```

Reproduced byte-for-byte from the first rule document of `detections/sigma_t1190.yml`.
Three further documents ship in that file: the blocked base rule (`low`), a
sustained-probing correlation over blocked attempts (`medium`), and the oversize-body
context rule (`informational`). **Deploy the file, not this excerpt.**

**What these rules structurally cannot do.** They cannot show you the payload — **the body
is never in the WAF log**. WAF records headers and the query string only. `matchedData`
helps partly: match details are populated **only for SQL-injection and XSS match
statements**, so the `SQLi_*` rules populate it while the regex-based
`SQLiExtendedPatterns_*` rules return an empty array. And they cannot see a body past the
inspection limit at all. Full reasoning in `detections/detection_note_t1190.md`.

---

### Key Investigation Queries

> WAF traffic logs go to CloudWatch Logs, S3 or Firehose — **not** to CloudTrail, and only if `PutLoggingConfiguration` was called for this web ACL. The CloudWatch Logs group is named `aws-waf-logs-*` and its streams are `<Region>_<web-acl-name>_<n>`. Adjust the log-group name below.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: which requests matched, and which were served

```bash
REGION="us-east-1"
LOG_GROUP="aws-waf-logs-<your-suffix>"        # must begin aws-waf-logs-
WINDOW_MS=$(( ( $(date +%s) - 86400 ) * 1000 ))

aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" --region "$REGION" \
  --start-time "$WINDOW_MS" \
  --filter-pattern '{ $.labels[0].name = "*SQLi*" }' \
  --output json > /tmp/waf-sqli.json

# labels is an array of SINGLE-KEY OBJECTS: [{"name":"..."}] — read .name, not the array.
# There is no httpRequest.host; the Host value is inside the headers array.
jq -r '.events[].message | fromjson |
  select([.labels[]?.name] | any(. // "" | test("SQLi_Body|SQLiExtendedPatterns_Body"))) |
  {time: (.timestamp/1000 | todate),
   action: .action,
   reached: (if .action == "ALLOW" then "SERVED-TO-BACKEND" else "stopped" end),
   client: .httpRequest.clientIp,
   country: .httpRequest.country,
   host: ([.httpRequest.headers[]? | select(.name|ascii_downcase=="host") | .value] | first),
   uri: .httpRequest.uri,
   args: .httpRequest.args,
   labels: [.labels[]?.name],
   body_truncated: ((.oversizeFields // []) | any(. == "REQUEST_BODY" or . == "REQUEST_JSON_BODY")),
   terminating: .terminatingRuleId,
   webacl: .webaclId}' /tmp/waf-sqli.json | jq -s 'sort_by(.time)'
```

Every row with `reached: "SERVED-TO-BACKEND"` is the incident — the request went to the
application **and** the control was configured not to stop it. `body_truncated: true`
alongside it means the rule inspected only the first 8–16 KB while the application received
all of it, so the payload you can see is not necessarily the payload that ran. Rows showing
`stopped` are the control working; count them per `client` as a targeting signal, and never
merge them into the same verdict. Record `client`, `host`, `uri` and the `webacl` ARN.

#### Query 2 — Establish why it was allowed: read the web ACL's own configuration

The log says the request was allowed. Only the configuration says why, and it is the
finding.

```bash
REGION="us-east-1"
WEB_ACL_ARN="<webacl-from-Query-1>"
NAME=$(printf '%s' "$WEB_ACL_ARN" | awk -F'/' '{print $(NF-1)}')
ID=$(printf '%s' "$WEB_ACL_ARN"   | awk -F'/' '{print $NF}')
SCOPE="REGIONAL"                               # CLOUDFRONT for a CloudFront distribution

ACL=$(aws wafv2 get-web-acl --name "$NAME" --scope "$SCOPE" --id "$ID" \
        --region "$REGION" --output json)
if [ -z "$ACL" ]; then
  echo "[!] get-web-acl returned nothing — wrong scope, wrong Region, or missing"
  echo "    wafv2:GetWebACL. INCONCLUSIVE, not clean."
else
  printf '%s' "$ACL" | jq -r '
    .WebACL.Rules[]
    | select(.Statement.ManagedRuleGroupStatement.Name == "AWSManagedRulesSQLiRuleSet")
    | {group: .Statement.ManagedRuleGroupStatement.Name,
       group_overridden_to_count: (.OverrideAction | has("Count")),
       rules_overridden: [.Statement.ManagedRuleGroupStatement.RuleActionOverrides[]?
                          | {rule: .Name, to: (.ActionToUse | keys[0])}],
       rules_excluded:  [.Statement.ManagedRuleGroupStatement.ExcludedRules[]?.Name]}'
  printf '%s' "$ACL" | jq -e '[.WebACL.Rules[].Statement.ManagedRuleGroupStatement.Name]
                              | any(. == "AWSManagedRulesSQLiRuleSet")' >/dev/null 2>&1 \
    || echo "[!] AWSManagedRulesSQLiRuleSet is NOT associated with this web ACL — the label could not have come from it; re-check the label namespace in Query 1"
fi
```

`group_overridden_to_count: true` is the answer in most cases: the whole group is
evaluating and labelling but not blocking. Otherwise look for the matched rule name in
`rules_overridden` or `rules_excluded`. If the group is absent entirely, the label came
from somewhere else and Query 1's `labels` field tells you which namespace. Also check
whether `SizeRestrictions_BODY` is present and not overridden — if it is, oversize padding
is blocked and the body rules are sound.

#### Query 3 — Sweep: the same signature across every web ACL

```bash
REGION="us-east-1"
LOG_GROUP="aws-waf-logs-<name>"
START=$(date -u -v-7d +%s 2>/dev/null || date -u -d '7 days ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string 'fields webaclId, action, terminatingRuleId, httpRequest.clientIp,
                         httpRequest.uri, httpRequest.country
                  | stats count() as hits,
                          count_distinct(`httpRequest.clientIp`) as clients,
                          count_distinct(`httpRequest.uri`) as paths
                          by webaclId, terminatingRuleId, action
                  | sort hits desc
                  | limit 200')

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'

echo
echo "[i] Repeat per web ACL log group. Logging is configured PER WEB ACL, so an ACL with no"
echo "    logging configuration produces nothing here and its silence is not evidence."
```

Read `action` first: rows with `ALLOW` are requests that reached the application and are the
only ones that matter for containment. `clients` separates one determined actor from broad
background scanning, and `paths` separates a targeted endpoint from a sweep. A `terminatingRuleId`
of `Default_Action` means no rule matched at all — the request was allowed because nothing
stopped it, which is a different finding from a rule deciding to allow it.

#### Query 4 — Full session reconstruction of the client

```bash
REGION="us-east-1"
LOG_GROUP="aws-waf-logs-<name>"
CLIENT="<httpRequest.clientIp-from-Query-1>"
START=$(date -u -v-7d +%s 2>/dev/null || date -u -d '7 days ago' +%s)
END=$(date -u +%s)

QID=$(aws logs start-query --log-group-name "$LOG_GROUP" \
  --start-time "$START" --end-time "$END" --region "$REGION" \
  --output text --query queryId \
  --query-string "fields @timestamp, action, terminatingRuleId, labels.0.name,
                         httpRequest.uri, httpRequest.httpMethod, httpRequest.country
                  | filter httpRequest.clientIp = '${CLIENT}'
                  | sort @timestamp asc
                  | limit 1000")

until [ "$(aws logs get-query-results --query-id "$QID" --region "$REGION" \
           --output text --query status)" != "Running" ]; do sleep 3; done
aws logs get-query-results --query-id "$QID" --region "$REGION" --output json | \
  jq -r '.results[] | map({(.field): .value}) | add'
```

The sequence is the evidence: a run of `BLOCK` followed by an `ALLOW` is an actor finding the
gap, and the `ALLOW` is the request the application actually processed. `labels` shows which
managed-rule components matched even where the terminating action was allow, so a request that
matched three signature families and still passed is worth more attention than ten that were
blocked.

**The client address may be a proxy.** Where CloudFront or another proxy fronts the web ACL,
correlate on `httpRequest.headers` for the forwarded-for value rather than trusting `clientIp`.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Two independent things are wrong: a request reached the application, and the control is
off. Restore the control first — it is one API call and it stops the next request — then
deal with what the served request may have done.

> Run under the **break-glass responder credentials** from §1, not under any principal that
> may have made the configuration change.

#### Step 1 — Restore the rule group to Block

```bash
REGION="us-east-1"; NAME="<web-acl-name>"; ID="<web-acl-id>"; SCOPE="REGIONAL"

# get-web-acl returns a LockToken that update-web-acl requires; it prevents you from
# overwriting a concurrent change. Capture the whole ACL — update-web-acl REPLACES the
# rule set, so a partial document silently deletes every rule you leave out.
CUR=$(aws wafv2 get-web-acl --name "$NAME" --scope "$SCOPE" --id "$ID" \
        --region "$REGION" --output json)
if [ -z "$CUR" ]; then
  echo "[!] Could not read the web ACL — do not attempt an update from a partial document."
else
  printf '%s' "$CUR" > /tmp/webacl-before.json
  echo "[OK] Captured pre-change web ACL to /tmp/webacl-before.json ($(printf '%s' "$CUR" | jq '.WebACL.Rules | length') rules)"
  echo "[i] Remove OverrideAction.Count / RuleActionOverrides / ExcludedRules for"
  echo "    AWSManagedRulesSQLiRuleSet in that file, then apply it whole:"
  echo "    aws wafv2 update-web-acl --name $NAME --scope $SCOPE --id $ID --region $REGION \\"
  echo "      --lock-token \$(jq -r '.LockToken' /tmp/webacl-before.json) \\"
  echo "      --default-action file://default-action.json --visibility-config file://vis.json \\"
  echo "      --rules file://rules-corrected.json"
fi
```

> **`update-web-acl` replaces the entire rule set.** There is no partial update. Applying a
> document that omits rules deletes them, which turns a control-restoration into an outage.
> Capture first, edit that capture, apply it whole.

#### Step 2 — Contain the principal that changed the configuration

The override was a `wafv2:UpdateWebACL` call and it is in CloudTrail.

```bash
REGION="us-east-1"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateWebACL \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | select(.errorCode == null) |
    {time: .eventTime, caller: .userIdentity.arn, ip: .sourceIPAddress,
     acl: .requestParameters.name}'

SUSPECT_ARN="<caller-arn-from-the-output-above>"
if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')        # user ARN: name = LAST segment
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyWafWrite" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["wafv2:UpdateWebACL","wafv2:DeleteLoggingConfiguration","wafv2:PutLoggingConfiguration"],"Resource":"*"}]}' \
    && echo "[OK] Denied further WAF writes by user $U"
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')         # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyWafWrite" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["wafv2:UpdateWebACL","wafv2:DeleteLoggingConfiguration","wafv2:PutLoggingConfiguration"],"Resource":"*"}]}' \
    && echo "[OK] Denied further WAF writes by role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

> If the override was a deliberate, time-boxed Count evaluation by your own team, this is
> not an incident — but the injection that reached the application still is. Treat the two
> findings separately.

---

## 4. Eradication

### Remove Attacker Access

The WAF side is closed once the rule group blocks again. What remains is the application
side, and WAF cannot tell you any of it:

- **Retrieve the request body from the application**, not from WAF — it is never in the log.
  Use `httpRequest.requestId` from Query 1 to join to the application or ALB access log
  (for ALB this field is the **trace ID**)
- **Determine whether the injection succeeded.** Database error logs, slow-query logs and
  the application's own logs around the timestamps from Query 1. A matched pattern is an
  *attempt*; only the database says whether it executed
- **If it executed**, treat the database credentials the application holds as exposed and
  rotate them, and scope what that identity could read
- **Sweep for the same client across other paths** — Query 1 filtered to SQLi labels;
  re-run it without the label filter for that `clientIp` to see what else was tried
- **Remove the emergency deny policy** once the configuration is verified restored

---

## 5. Recovery

### Restore Clean State

#### Verify the rule group blocks again

```bash
REGION="us-east-1"; NAME="<web-acl-name>"; ID="<web-acl-id>"; SCOPE="REGIONAL"

ACL=$(aws wafv2 get-web-acl --name "$NAME" --scope "$SCOPE" --id "$ID" --region "$REGION" --output json)
if [ -z "$ACL" ]; then
  echo "[!] get-web-acl returned nothing — INCONCLUSIVE, not clean."
else
  BAD=$(printf '%s' "$ACL" | jq '[.WebACL.Rules[]
        | select(.Statement.ManagedRuleGroupStatement.Name == "AWSManagedRulesSQLiRuleSet")
        | select((.OverrideAction | has("Count"))
                 or ((.Statement.ManagedRuleGroupStatement.RuleActionOverrides // []) | length > 0)
                 or ((.Statement.ManagedRuleGroupStatement.ExcludedRules // []) | length > 0))] | length')
  PRESENT=$(printf '%s' "$ACL" | jq '[.WebACL.Rules[].Statement.ManagedRuleGroupStatement.Name]
            | map(select(. == "AWSManagedRulesSQLiRuleSet")) | length')
  if [ "${PRESENT:-0}" -eq 0 ]; then
    echo "[FAIL] AWSManagedRulesSQLiRuleSet is not associated with this web ACL at all"
  elif [ "${BAD:-1}" -eq 0 ]; then
    echo "[OK] SQLi rule group is present with no Count override, action override or exclusion"
  else
    echo "[FAIL] SQLi rule group is still overridden or has excluded rules"
  fi
fi
```

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     a log record whose labels[].name ends ':SQLi_Body' or"
echo "                  ':SQLiExtendedPatterns_Body' AND whose action is ALLOW"
echo "                  -> waf_sqli_body_allowed, level high"
echo "MUST NOT fire on: the same label with action BLOCK, CAPTCHA or CHALLENGE — those did"
echo "                  not reach the application and belong to the volume correlation"
echo "EXPECTED, by design: an allowed request whose oversizeFields names REQUEST_BODY fires"
echo "                  BOTH the high rule and the informational one. That is the point —"
echo "                  the second says the rule inspected less than the application received."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| An SQL-injection body reached the application | The managed SQLi rule group was overridden to Count, or the matching rule excluded — the control was evaluating and labelling but not blocking |
| Nobody was alerted while the control was working | The deployed rule gated on `action: ALLOW`, so blocked attempts raised nothing and the only firing condition was the control being off |
| The payload could not be recovered from WAF | The request body is never written to the WAF log; no application-side capture was joined to `httpRequest.requestId` |
| A padded body would have bypassed inspection entirely | Body inspection is capped at 8 KB on ALB, oversize handling is `Continue`, and `SizeRestrictions_BODY` was not enforced |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// Reserve web ACL and logging changes to the security-tooling pipeline. Both are needed:
// UpdateWebACL turns the protection off, PutLoggingConfiguration turns the evidence off.
{
  "Effect": "Deny",
  "Action": ["wafv2:UpdateWebACL", "wafv2:DeleteLoggingConfiguration", "wafv2:PutLoggingConfiguration"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/security-tooling" }
  }
}
```

> `aws:PrincipalArn` carries a wildcard here, so it needs `ArnNotLike` — `StringNotEquals`
> does not expand `*`. In a `Deny`, the equality form would match every request and deny
> everything, which is an outage rather than a bypass.

- **Enforce `SizeRestrictions_BODY`** — it blocks bodies over 8,192 bytes and closes the
  padding evasion outright. Check it is present and not overridden before relying on any
  body rule
- **Alarm on `OverrideAction: Count` persisting beyond a change window.** Count mode is a
  legitimate evaluation tool and an effective off switch; what makes it an incident is
  duration
- **Parameterise the queries.** WAF is compensating for an application defect; the durable
  fix is upstream

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1190 — Exploit Public-Facing Application |
| MITRE tactic | Initial Access (TA0001) |
| Primary API | None — this is request traffic. The enabling change is `wafv2:UpdateWebACL` |
| Event source | AWS WAF web ACL traffic log — **not CloudTrail**, and **off by default** (`wafv2:PutLoggingConfiguration`) |
| Key discriminator | The `SQLi_Body` / `SQLiExtendedPatterns_Body` label **together with** `action: ALLOW`. The action is a verdict axis, never a filter |
| Field-shape traps | `labels` is an array of single-key objects (`labels[].name`), not strings. **There is no `httpRequest.host`** — Host is inside `headers[]`. `webaclId` holds the ARN. `matchedData` is populated only for SQLi/XSS match statements, so `SQLiExtendedPatterns_*` returns an empty array |
| Blast radius | The application and whatever its database identity can reach. The body is not in the log, so the ceiling must be established application-side |
| Evasion | Body inspection caps at 8 KB (ALB/AppSync, fixed) or 16 KB (default elsewhere); managed body rules use `Continue`; AWS forwards the **entire** body regardless. `oversizeFields` records it |
| Absence caveat | `AWSManagedRulesSQLiRuleSet` is not part of a baseline deployment. No association means no label means no alert — a configuration answer before a traffic answer |

### Residual Risk

**What the application received is not in your WAF logs and never will be.** The body is
not recorded. If the application did not log the request itself, the payload is
unrecoverable, and "an SQLi pattern matched" is the entire extent of what can be known.

**Restoring the rule group does not undo the request that was served.** If the injection
executed, the database acted on it before any of this began; the WAF change prevents the
next one only.

**The padding evasion remains open unless `SizeRestrictions_BODY` is enforced.** Blocking
at the rule group closes the case you detected. An attacker who pads past 8 KB is not
detected at all — `oversizeFields` shows the truncation, but no body rule fires, so nothing
alerts.

**A blocked attempt is still reconnaissance.** The volume correlation surfaces sustained
probing, but a single blocked injection raises P3 and will usually be dismissed. That is
the right disposition and it means low-and-slow mapping of your parameters is, in practice,
invisible.
