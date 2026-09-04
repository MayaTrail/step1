# IR Playbook: Known-Bad IP with Allowed Web Attack — `AWSManagedIPReputationList` and a composite that evaluation order usually prevents

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Exploitation of a public-facing application from an address AWS lists as malicious, served to the backend |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High** when the reputation label came from a Block-action list, because that combination is only reachable if the reputation group was overridden to Count — the protection is off. **Medium** when it came from `AWSManagedIPDDoSList`, which is Count by design and whose label alongside an attack is the expected shape rather than an anomaly. The source rule rates the whole thing P2 and cannot tell the two apart |
| MITRE Tactics | Initial Access |
| MITRE Techniques | T1190 |
| Services in Scope | WAF, the protected resource (ALB / CloudFront / API Gateway / AppSync), the application, CloudTrail (for the configuration change), IAM |

**What the technique does:** a request arrives from an address in an AWS managed IP-reputation list
carrying a web-attack payload. WAF evaluates its rules in priority order, and both facts
have to be labelled onto **one request in one evaluation** for the composite to exist —
there is no cross-request correlation here, both labels land in the same record's `labels[]`
array. Whether that can happen is decided entirely by which rule terminates first.

**Detection thesis.** The signal is which reputation list matched, not merely that one did.
`AWSManagedIPDDoSList` is **Count** and lets evaluation continue; `AWSManagedIPReputationList`
and `AWSManagedReconnaissanceList` are **Block** and stop it, so an attack label cannot be
added after them. The source rule requires both labels plus `action: ALLOW`, which at AWS
defaults leaves it covering one of its three lists — and its silence reads as "no attacker"
when it means "evaluation order".

---

## 1. Preparation

**Logging & Visibility**
- **WAF traffic logs are not CloudTrail and are off by default**, enabled per web ACL by
  `wafv2:PutLoggingConfiguration` and by nothing else. Without it WAF still evaluates and
  blocks, and writes no request record anywhere
- Record fields this playbook reads: `action`, `labels[].name` (an array of **single-key
  objects**, not strings), `httpRequest.clientIp`, `.country`, `.uri`, `.headers[]` (a
  `{name,value}` array — **there is no `httpRequest.host`**), `terminatingRuleId`,
  `ruleGroupList[]`, `webaclId` (holding the **ARN**)
- **The rule priority order of the web ACL**, recorded before an incident. It determines
  which of these signals can coexist, and it is not in the log record
- **Whether `AWSManagedRulesAmazonIpReputationList` is at its default actions.** An override
  to Count changes what every finding here means
- CloudTrail management events for `wafv2:UpdateWebACL`

**Alerting (must be pre-configured)**
- **Attack label with a Block-action reputation label and `action: ALLOW` — the reputation group is overridden → P0**
- **Attack label with `AWSManagedIPDDoSList` and `action: ALLOW` — expected shape, judge the attack → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under investigation, and `jq`.
- CloudWatch Logs Insights access for the log group named in **Logging & Visibility**, and the patience for `start-query` to settle before reading results.
- The service's own configuration in version control, to compare live state against a known-good baseline rather than against recollection.

**Known IOC Baselines**
- Which principals and automation roles touch this service at all. In most estates the list is short, which makes an unfamiliar caller a finding before any threshold is evaluated.
- **The normal value for this measure, per resource, from a quiet week.** The rule compares against a resource's own history rather than a fleet average, so without the baseline the threshold is a guess.
- The expected account IDs, Regions and resource names for this service, so an unfamiliar one is recognisable without a lookup during triage.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | Attack label with `AWSManagedIPReputationList` / `AWSManagedReconnaissanceList` / `AnonymousIPList` / `HostingProviderIPList` and `action: ALLOW` | WAF traffic log | T1190 |
| P1 | Attack label with `AWSManagedIPDDoSList` and `action: ALLOW` — the Count-by-default list | WAF traffic log | T1190 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | Fifty or more **blocked** requests from one reputation-listed address to one host in 10 minutes | WAF traffic log | T1190 |
| P3 | A reputation-listed address served with no attack label — evaluation may have terminated before the attack groups ran | WAF traffic log | T1190 |

### Detection Rule Quality Notes

The source rule requires a combination that AWS's own default evaluation order prevents,
and reports nothing when the control works.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Requires a reputation label **and** an attack label on one request | With the reputation group first, a match on either Block-action list **terminates evaluation** — the attack groups never run and no attack label is ever added. Reversed order, the attack rule terminates first and the reputation label is never added. Either way the composite cannot form | Alert on the composite where it is genuinely reachable, and ship the blocked-at-reputation case as its own base rule and volume correlation |
| Treats all three reputation lists as equivalent | `AWSManagedIPDDoSList` is **Count** by default and the other two are **Block**. So the rule effectively covers only the DDoS list — where the combination is *expected* — while the two lists that matter are structurally excluded | Split the verdict: a Block-list label with `ALLOW` means the group is overridden (P0); a DDoS-list label with `ALLOW` is the normal shape (P1, judge the attack) |
| Gates on `action:"ALLOW"` | A reputation-listed address that was blocked raises nothing at all, so the most common real observation — and the targeting signal that precedes an attack — is discarded | Terminating action as a **verdict axis**, never a filter |
| Matches attack labels by loose regex alternation | Workable, but the label is not derivable from the rule name and casing is not uniform: one group ships `SQLi_URIPath` and `SQLiExtendedPatterns_UriPath` | Match the component-independent stem (`:SQLi_`, `:EC2MetaDataSSRF_`) and read the component off the matched label |
| Assumes "known-bad" includes customer blocklists | A customer `IPSet` produces **no label** unless the customer's own rule adds one with `RuleLabels`, so a label-matching rule cannot see it | Documented explicitly; if you want your own blocklist covered, add `RuleLabels` to that rule |

**Recommended detection — reputation label and attack label on one served request.**

```yaml
# Known-Bad IP with Allowed Web Attack (T1190)
#
# The source rule requires a reputation label AND an attack label AND action:"ALLOW" on one
# request. At AWS managed defaults that combination is nearly unreachable, and the reason is
# evaluation order rather than traffic.
#
# Rules run in priority order and a TERMINATING action ends evaluation immediately — nothing
# after it runs, and nothing after it labels. Labels are visible only to rules running after
# the rule that added them. So:
#
#   * AWSManagedIPReputationList and AWSManagedReconnaissanceList are BLOCK. If the
#     reputation group runs first, as it usually does, a match blocks and stops evaluation:
#     the CRS / SQLi / known-bad-inputs groups never run and NO ATTACK LABEL IS EVER ADDED.
#   * AWSManagedIPDDoSList is COUNT. It labels and evaluation continues. It is the only one
#     of the three whose label can coexist with an attack label at defaults.
#   * If the reputation group runs AFTER the attack groups, an attack the attack group blocks
#     terminates first and the reputation label is never added.
#
# So the source rule covers one of its three reputation lists, and only when the attack rule
# that also matched did not terminate. Its silence means "evaluation order", not "no attacker".
#
# Rules 1 and 2 below split what the source rule conflates: the reachable case, and the
# blocked-at-reputation case that the source rule discards entirely by gating on ALLOW.
title: Request from a reputation-listed address carried a web attack and reached the application
id: 7e6d5a41-2b8c-4f37-9e0d-5c1a4b83f206
name: waf_badip_attack_allowed
status: experimental
description: >-
  One request carried both an AWS IP-reputation label and a web-attack label, and was served
  to the backend. At defaults this means the reputation match was the Count-action DDoS list,
  or the reputation group was overridden to Count.
references:
  - https://attack.mitre.org/techniques/T1190/                                # retrieved 2026-08-30
  - https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-ip-rep.html  # retrieved 2026-08-30
tags:
  - attack.initial-access
  - attack.t1190
logsource:
  product: aws
  service: waf
detection:
  reputation_label:
    labels.name|endswith:
      - ':AWSManagedIPReputationList'
      - ':AWSManagedReconnaissanceList'
      - ':AWSManagedIPDDoSList'
      - ':AnonymousIPList'
      - ':HostingProviderIPList'
  # Stems, not full labels: the component suffix differs per rule and its casing is not
  # mechanically derivable (SQLi_URIPath vs SQLiExtendedPatterns_UriPath in one group).
  attack_label:
    labels.name|contains:
      - ':SQLi_'
      - ':SQLiExtendedPatterns_'
      - ':GenericLFI_'
      - ':GenericRFI_'
      - ':CrossSiteScripting_'
      - ':EC2MetaDataSSRF_'
      - ':Log4JRCE_'
      - ':JavaDeserializationRCE_'
      - ':ReactJSRCE_'
      - ':PHPHighRiskMethodsVariables_'
      - ':WindowsShellCommands_'
      - ':PowerShellCommands_'
      - ':UNIXShellCommandsVariables_'
  reached_backend:
    action: 'ALLOW'
  condition: reputation_label and attack_label and reached_backend
falsepositives:
  - A shared NAT or proxy egress whose address is reputation-listed for someone else's
    traffic. The reputation group uses the web request ORIGIN address, so behind a proxy or
    a second load balancer it sees the proxy. Confirm the client before acting on the IP.
level: high
---
# The case the source rule discards. A reputation-listed address that was BLOCKED carries no
# attack label — evaluation stopped before the attack groups ran — so a rule requiring both
# labels can never see it. It is still the most common real observation, and at volume from
# one address it is the targeting signal that precedes everything else.
title: Reputation-listed address blocked at the edge
id: 9a1f3c27-4e58-4b06-8d3f-6b2e07a95d18
name: waf_badip_blocked
status: experimental
description: Base rule — volume component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-ip-rep.html  # retrieved 2026-08-30
tags:
  - attack.initial-access
  - attack.t1190
logsource:
  product: aws
  service: waf
detection:
  reputation_label:
    labels.name|endswith:
      - ':AWSManagedIPReputationList'
      - ':AWSManagedReconnaissanceList'
      - ':AnonymousIPList'
      - ':HostingProviderIPList'
  stopped:
    action:
      - 'BLOCK'
      - 'CAPTCHA'
      - 'CHALLENGE'
  condition: reputation_label and stopped
level: low
---
# Threshold basis, stated rather than invented: this counts BLOCKED requests from listed
# addresses, so it is a targeting signal and the control is working. A public endpoint sees
# background reputation traffic continuously, so the value is set where one address's
# sustained attention against one host separates from ambient scanning. Baseline against
# your own edge before deploying.
title: Sustained attempts from reputation-listed addresses against one host
id: c3852be0-71fa-4d29-a6b4-8f0e27d514ab
status: experimental
description: >-
  One reputation-listed address sent fifty or more blocked requests to a single host in ten
  minutes — sustained targeting rather than background scanning.
references:
  - https://attack.mitre.org/techniques/T1190/                                # retrieved 2026-08-30
tags:
  - attack.initial-access
  - attack.t1190
correlation:
  type: event_count
  rules:
    - waf_badip_blocked
  group-by:
    - httpRequest.clientIp
    - webaclId
  timespan: 10m
  condition:
    gt: 49
level: medium
```

Reproduced byte-for-byte from the first rule document of `detections/sigma_t1190.yml`. Two
further documents ship in that file: the blocked-at-reputation base rule (`low`) and a
sustained-targeting correlation over blocked requests (`medium`). **Deploy the file, not
this excerpt.**

**What these rules structurally cannot do.** They cannot see an attack that was blocked at
the reputation group, because no attack label exists for it — that information does not
exist in the record and no rule can recover it. They cannot identify the true client behind
a proxy: the reputation group evaluates the **request origin**, so a listed address may be
your own edge. And they cannot show a request body. Full reasoning in
`detections/detection_note_t1190.md`.

---

### Key Investigation Queries

> WAF traffic logs go to CloudWatch Logs, S3 or Firehose — **not** CloudTrail — and only if `PutLoggingConfiguration` was called for this web ACL. The log group is named `aws-waf-logs-*`.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: which list matched, what else matched, and was it served

```bash
REGION="us-east-1"
LOG_GROUP="aws-waf-logs-<your-suffix>"
WINDOW_MS=$(( ( $(date +%s) - 86400 ) * 1000 ))

aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" --region "$REGION" \
  --start-time "$WINDOW_MS" --output json > /tmp/waf-rep.json

# labels is an array of SINGLE-KEY OBJECTS: [{"name":"..."}] — read .name.
# There is no httpRequest.host; Host lives inside the headers array.
jq -r '.events[].message | fromjson |
  ([.labels[]?.name] // []) as $L |
  select($L | any(. // "" | test("AWSManagedIPReputationList|AWSManagedReconnaissanceList|AWSManagedIPDDoSList|AnonymousIPList|HostingProviderIPList"))) |
  {time: (.timestamp/1000 | todate),
   action: .action,
   reached: (if .action == "ALLOW" then "SERVED-TO-BACKEND" else "stopped" end),
   client: .httpRequest.clientIp,
   xff: ([.httpRequest.headers[]? | select(.name|ascii_downcase=="x-forwarded-for") | .value] | first),
   country: .httpRequest.country,
   uri: .httpRequest.uri,
   rep_list: [$L[] | select(test("AWSManaged|AnonymousIPList|HostingProviderIPList"))],
   attack: [$L[] | select(test("SQLi_|GenericLFI_|GenericRFI_|CrossSiteScripting_|EC2MetaDataSSRF_|Log4JRCE_|JavaDeserializationRCE_|ReactJSRCE_|PHPHighRiskMethodsVariables_|WindowsShellCommands_|PowerShellCommands_|UNIXShellCommandsVariables_"))],
   terminating: .terminatingRuleId,
   webacl: .webaclId}' /tmp/waf-rep.json | jq -s 'sort_by(.time)'
```

A row with a non-empty `attack`, `reached: "SERVED-TO-BACKEND"` and a `rep_list` naming
anything other than `AWSManagedIPDDoSList` is the P0 case: that combination is only
reachable if the reputation group was overridden, so **check the configuration in Query 2
before treating it as a traffic event.** The same row naming only `AWSManagedIPDDoSList` is
the expected shape — that list is Count by design — so judge it on the `attack` label and
treat the address as context. Rows with an empty `attack` and `reached: "stopped"` are the
control working; count them per `client`. Note `xff` — the reputation group evaluated
`client`, which behind a proxy is the intermediary rather than the true source, and `xff` is
attacker-controllable.

#### Query 2 — Establish the evaluation order and the reputation group's actions

The log cannot tell you why a combination was or was not possible. The web ACL can.

```bash
REGION="us-east-1"; NAME="<web-acl-name>"; ID="<web-acl-id>"; SCOPE="REGIONAL"

ACL=$(aws wafv2 get-web-acl --name "$NAME" --scope "$SCOPE" --id "$ID" --region "$REGION" --output json)
if [ -z "$ACL" ]; then
  echo "[!] get-web-acl returned nothing — wrong scope, wrong Region, or missing"
  echo "    wafv2:GetWebACL. INCONCLUSIVE, not clean."
else
  printf '%s' "$ACL" | jq -r '
    .WebACL.Rules
    | sort_by(.Priority)
    | map({priority: .Priority,
           name: .Name,
           group: (.Statement.ManagedRuleGroupStatement.Name // "custom"),
           overridden_to_count: ((.OverrideAction // {}) | has("Count")),
           rule_overrides: [.Statement.ManagedRuleGroupStatement.RuleActionOverrides[]?
                            | {rule: .Name, to: (.ActionToUse | keys[0])}]})'
fi
```

Read it in priority order. If `AWSManagedRulesAmazonIpReputationList` sits **before** the
attack groups and is not overridden, the P0 composite is impossible by construction and any
Query 1 row showing it needs re-examining — most likely the reputation label came from the
DDoS list. If it **is** overridden to Count, the P0 case is reachable and the override is
the finding. If it sits **after** the attack groups, attacks that terminate are never
reputation-labelled, and the composite is suppressed from the other direction.

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

Decide first which incident you have. An overridden reputation group is a control failure to
be corrected. A DDoS-list label alongside an attack is an ordinary web attack from a noisy
address, and the address is not the point. Do not block an IP and call it contained.

> Run under the **break-glass responder credentials** from §1, not under any principal that
> may have changed the web ACL.

#### Step 1 — If the reputation group was overridden, restore it

```bash
REGION="us-east-1"; NAME="<web-acl-name>"; ID="<web-acl-id>"; SCOPE="REGIONAL"

# update-web-acl REPLACES the entire rule set and requires the LockToken from get-web-acl.
# Capture the whole document first — applying a partial one deletes every rule you omit.
CUR=$(aws wafv2 get-web-acl --name "$NAME" --scope "$SCOPE" --id "$ID" --region "$REGION" --output json)
if [ -z "$CUR" ]; then
  echo "[!] Could not read the web ACL — do not attempt an update from a partial document."
else
  printf '%s' "$CUR" > /tmp/webacl-before.json
  echo "[OK] Captured pre-change web ACL ($(printf '%s' "$CUR" | jq '.WebACL.Rules | length') rules) to /tmp/webacl-before.json"
  echo "[i] Remove OverrideAction.Count and RuleActionOverrides from the reputation group in"
  echo "    that file, then apply it WHOLE with --lock-token \$(jq -r .LockToken /tmp/webacl-before.json)"
fi
```

#### Step 2 — Contain the principal that changed it

```bash
REGION="us-east-1"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateWebACL \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | select(.errorCode == null) |
    {time: .eventTime, caller: .userIdentity.arn, ip: .sourceIPAddress, acl: .requestParameters.name}'

SUSPECT_ARN="<caller-arn-from-the-output-above>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["wafv2:UpdateWebACL","wafv2:PutLoggingConfiguration","wafv2:DeleteLoggingConfiguration"],"Resource":"*"}]}'
if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')       # user ARN: name = LAST segment
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyWafWrite" \
    --policy-document "$DENY" && echo "[OK] Denied further WAF writes by user $U"
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')        # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyWafWrite" \
    --policy-document "$DENY" && echo "[OK] Denied further WAF writes by role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

> Blocking the source address buys time and nothing more. The reputation group carries **no
> versioning and no update notifications**, so its contents change without telling you, and
> the attacker changes address more cheaply than you change rules. Fix the application defect
> the attack label named.

---

## 4. Eradication

### Remove Attacker Access

- **Work the attack label, not the address.** The `attack` array from Query 1 names the class
  — SQLi, LFI, RFI, XSS, SSRF, Log4j, deserialisation. Treat the corresponding application
  defect as the incident and use the matching sibling playbook where one exists
- **Retrieve the request from the application** using `httpRequest.requestId` (for ALB this
  is the **trace ID**). The body is never in the WAF log
- **Re-run Query 1 without the reputation filter** for the same `clientIp` — the reputation
  hit is one slice of what that address attempted
- **If the reputation group was overridden**, find every other web ACL with the same override:
  the change was probably not made to one ACL alone
- **Remove the emergency deny policy** once the configuration is verified restored

---

## 5. Recovery

### Restore Clean State

#### Verify the reputation group is at its default actions

```bash
REGION="us-east-1"; NAME="<web-acl-name>"; ID="<web-acl-id>"; SCOPE="REGIONAL"

ACL=$(aws wafv2 get-web-acl --name "$NAME" --scope "$SCOPE" --id "$ID" --region "$REGION" --output json)
if [ -z "$ACL" ]; then
  echo "[!] get-web-acl returned nothing — INCONCLUSIVE, not clean."
else
  PRESENT=$(printf '%s' "$ACL" | jq '[.WebACL.Rules[].Statement.ManagedRuleGroupStatement.Name]
            | map(select(. == "AWSManagedRulesAmazonIpReputationList")) | length')
  BAD=$(printf '%s' "$ACL" | jq '[.WebACL.Rules[]
        | select(.Statement.ManagedRuleGroupStatement.Name == "AWSManagedRulesAmazonIpReputationList")
        | select(((.OverrideAction // {}) | has("Count"))
                 or (((.Statement.ManagedRuleGroupStatement.RuleActionOverrides) // []) | length > 0))] | length')
  if [ "${PRESENT:-0}" -eq 0 ]; then
    echo "[FAIL] AWSManagedRulesAmazonIpReputationList is not associated with this web ACL"
  elif [ "${BAD:-1}" -eq 0 ]; then
    echo "[OK] Reputation group present with no Count override and no rule action overrides"
  else
    echo "[FAIL] Reputation group is still overridden"
  fi
fi
```

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     one record whose labels carry BOTH a reputation label and an attack"
echo "                  label, with action ALLOW -> waf_badip_attack_allowed, level high"
echo "MUST NOT fire on: a reputation label with action BLOCK and no attack label — that is"
echo "                  the control working, and it belongs to the volume correlation"
echo "EXPECTED, by design: a record labelled AWSManagedIPDDoSList plus an attack label, with"
echo "                  action ALLOW. That list is Count by default, so this shape is normal."
echo "                  The rule fires; the KQL verdict downgrades it to P1. Judge the attack,"
echo "                  not the address. Do NOT retune the rule to suppress it."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A request from a listed address carrying an attack reached the application | The reputation group was overridden to Count, or the match came from the Count-action DDoS list and the attack rule was itself overridden |
| The deployed rule could not have fired for the two Block-action lists | It required a label combination that AWS's default evaluation order prevents — a terminating Block adds no subsequent labels |
| Blocked attempts from listed addresses raised nothing | The rule gated on `action: ALLOW`, discarding the targeting signal entirely |
| The true client could not be established from the alert | The reputation group evaluates the request origin; no `X-Forwarded-For` capture was in the triage path |

### Recommended Guardrails

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// The two calls that disable this control and its evidence, reserved to the security pipeline.
{
  "Effect": "Deny",
  "Action": ["wafv2:UpdateWebACL", "wafv2:PutLoggingConfiguration", "wafv2:DeleteLoggingConfiguration"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/security-tooling" }
  }
}
```

> The condition value carries a wildcard, so it needs `ArnNotLike`. Under `StringNotEquals`
> the wildcard is not expanded, the condition matches every request, and a `Deny` then denies
> everything — an outage rather than a bypass.

- **Record the web ACL's rule priority order in your baseline.** Which findings are even
  possible is decided by it, and it is absent from every log record
- **Add `RuleLabels` to your own `IPSet` rules** if you want your blocklist visible to
  label-matching detections — by default a customer IP set produces no label
- **Alarm on `OverrideAction: Count` persisting past a change window.** Count is a legitimate
  evaluation mode and an effective off switch; duration is what distinguishes them

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1190 — Exploit Public-Facing Application |
| MITRE tactic | Initial Access (TA0001) |
| Primary API | None — request traffic. The enabling change is `wafv2:UpdateWebACL` |
| Event source | AWS WAF web ACL traffic log — **not CloudTrail**, **off by default** |
| Key discriminator | Which reputation list matched. `AWSManagedIPDDoSList` is **Count** (label + attack is expected); `AWSManagedIPReputationList` and `AWSManagedReconnaissanceList` are **Block** (label + attack means the group was overridden) |
| Structural constraint | A terminating action ends evaluation and adds no further labels, so a Block at the reputation group means no attack label can exist. The composite is suppressed by either rule ordering |
| Field-shape traps | `labels` is an array of single-key objects (`labels[].name`). **No `httpRequest.host`** — Host is in `headers[]`. `webaclId` holds the ARN. A customer `IPSet` emits no label without `RuleLabels` |
| Blast radius | The application and what the attack class reaches. The address is context, not the ceiling |
| Attribution caveat | The reputation group evaluates the **request origin**, so behind a proxy or CDN it sees the intermediary. `X-Forwarded-For` is attacker-controllable |

### Residual Risk

**The absence of this alert is not evidence of absence.** At AWS defaults the composite it
detects is suppressed by evaluation order for two of three reputation lists. A quiet queue
here is consistent with a correctly configured web ACL blocking attacks all day, and equally
consistent with nobody trying.

**The reputation list is unversioned and unnotified.** Its contents change without warning,
so an address that matched today may not tomorrow, and a rule built on it cannot be
regression-tested against a fixed input.

**Blocking the address contains nothing durable.** The attacker's next request comes from a
different address; the application defect that the attack label named is still there.

**Behind a proxy the address may be yours.** If the origin address is your own CDN or load
balancer, a reputation match is meaningless and every IP-based response will hit your own
infrastructure.
