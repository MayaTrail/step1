# IR Playbook: Enumerate SES for Phishing Capability - Email-Abuse Reconnaissance via SES Read APIs

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Discovery / Cloud Service Reconnaissance (email-abuse pre-attack) |
| Emulation Tier | Atomic technique |
| Threat Actor | N/A, single-technique emulation, not actor-attributed |
| Platform | aws |
| Severity | Medium, reconnaissance only, but it is a targeted assessment of the account's ability to send mail, and the follow-on (phishing/spam from your verified domains and sender reputation) carries real blocklisting, financial, and reputational damage (`MANIFEST.py` rates LOW; the IR view is Medium because of what this recon is *for*) |
| MITRE Tactics | Discovery |
| MITRE Techniques | T1087 (as mapped by Stratus, a poor fit; see §6) |
| Services in Scope | SES / SESv2, CloudTrail, IAM |
| Infrastructure Created | None, the emulation reads existing SES configuration; it creates nothing |

**What the emulation does:** calls four read-only SES v1 APIs in sequence, `ses:GetAccountSendingEnabled` (is sending on?), `ses:GetSendQuota` (how much can we send?), `ses:ListIdentities` (which addresses/domains are verified?), and `ses:GetIdentityVerificationAttributes` (which of those are usable senders?). Together they answer one question: *can this account be used to send phishing or spam, and from whom?*

**Why the four calls together are the signal, not any one of them.** Individually these are benign: monitoring dashboards read `GetSendQuota` and `GetAccountSendingEnabled` routinely. What marks reconnaissance is the **fingerprint**, one principal running the *whole set* in a short window, especially culminating in `ListIdentities` + `GetIdentityVerificationAttributes`, which reveal the identities an attacker could impersonate. The shipped rule fires on any single call with no grouping (§2), so it both floods on benign dashboard reads and fails to key on the combination that actually matters.

**Why the SES version matters for detection.** The emulation uses the SES v1 API. The same reconnaissance is achievable through **SESv2** with different event names, `GetAccount` (which returns sending-enabled and quota in one call) and `ListEmailIdentities`. A detection that enumerates only the v1 event names is trivially evaded by an attacker who uses the v2 SDK. Cover both.

**Why this is Medium, not Low.** The calls are read-only and create nothing. But SES abuse is unusually damaging relative to other recon: an attacker who finds sending enabled, a high quota, and verified production domains can send convincing phishing *from your own domains*, burn your sender reputation, and get your sending IPs/domains blocklisted. Treat the recon as the early-warning it is.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail, management events `ReadWriteType: All`, delivered to S3 (versioned, MFA delete) and to CloudWatch Logs / a log platform for the fingerprint query
- **These SES calls are read events**, a `WriteOnly` trail misses them entirely. Confirm `ReadWriteType: All`
- SES sending-activity monitoring: CloudWatch SES metrics (Send, Bounce, Complaint, Reputation) and, ideally, SES event publishing to a destination so a post-recon send spike is visible fast
- An inventory of verified SES identities (domains and addresses) and the account's send quota / sandbox status, so "what could the attacker do with this?" is answerable immediately. Keep this as a maintained file (e.g. `known-good-identities.txt`, one identity per line), §5 diffs the live identity list against it to spot attacker-added senders

**Alerting (must be pre-configured)**
- Fingerprint alert: one principal calling **3 or more distinct SES read APIs** (across the v1 *and* v2 name sets) within 10 minutes → alert. This is the primary control; it keys on the combination, not any single call
- Any `ses:ListIdentities` / `ses:GetIdentityVerificationAttributes` / `sesv2:ListEmailIdentities` from a principal not on the small allowlist of SES operations/monitoring roles, these "who can I send as?" calls are the highest-signal part of the fingerprint
- **Follow-on abuse alerts (the ones that catch real damage):** a spike in `ses:SendEmail` / `ses:SendRawEmail` / `ses:SendBulkTemplatedEmail`; any `ses:UpdateAccountSendingEnabled` / sandbox-exit or quota-increase request; any new identity creation (`ses:VerifyEmailIdentity` / `ses:VerifyDomainIdentity` / `sesv2:CreateEmailIdentity`) by a non-operations principal

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under investigation
- `jq` installed
- A documented decision on whether pausing account-wide SES sending during an incident is acceptable (it stops the attack but also stops legitimate mail), decide the trade-off before you need it

**Known IOC Baselines**
- Baseline which principals call SES read APIs at all, normally a short list (the app that sends mail, a monitoring role). Recon shows up as an unfamiliar principal running the full read set
- Baseline normal send volume and identity list, so a spike or a new sender identity is obvious

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE: Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | One principal calls ≥ 3 distinct SES read APIs (v1 or v2) in 10 min, including at least one identity-enumeration call (`ListIdentities` / `GetIdentityVerificationAttributes` / `ListEmailIdentities`) | CloudTrail | T1087 |
| P0 | SES recon fingerprint immediately followed by a new identity verification | CloudTrail (management) | T1087 |
| P0 | SES recon fingerprint immediately followed by a `Send` volume spike | CloudWatch `AWS/SES` / SES event publishing (sends are data-plane, NOT in CloudTrail Event History) | T1087 |
| P1 | Any SES read from a principal not on the SES-operations allowlist | CloudTrail | T1087 |
| P1 | SES read burst from an off-baseline ASN/geography for the principal | CloudTrail | T1087 |

#### MEDIUM-CONFIDENCE: May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `ses:GetAccountSendingEnabled` + `ses:GetSendQuota` (or v2 `GetAccount`) from an unfamiliar principal, without identity enumeration | CloudTrail | T1087 |
| P2 | `ses:ListIdentities` alone from a principal with no send/monitoring history | CloudTrail | T1087 |
| P2 | SES read APIs denied at volume (`errorCode = AccessDenied`), permission probing | CloudTrail | T1087 |
| P3 | Single `ses:GetSendQuota` / `GetAccountSendingEnabled` from an allowlisted monitoring role | CloudTrail | T1087 |

### Detection Rule Quality Notes

The rules in `detections/` are too coarse and are evadable. These are correctness/noise defects.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Sigma/KQL match any of the four SES read events with `condition: selection`, no threshold, no per-principal grouping | Both noisy and imprecise. `GetSendQuota`/`GetAccountSendingEnabled` are read by dashboards and health checks; a 1:1 rule fires on benign monitoring. And matching any *single* call cannot express the recon *fingerprint* (the whole set together) | Threshold on **count of distinct SES read APIs per principal per window**; weight identity-enumeration calls highest |
| v1 event names only, no SESv2 coverage | Trivially evaded: an attacker using the SESv2 SDK produces `GetAccount` / `ListEmailIdentities`, which the rule never matches | Add the v2 event names to the selection |
| No allowlist / baseline | Cannot separate the app's own SES monitoring from an attacker | Compare against an SES-operations principal allowlist |
| No linkage to follow-on abuse | Detects the recon but not the send-abuse it precedes; the actual damage is unalerted | Add follow-on rules for send spikes, sandbox-exit, and new-identity creation |
| Header TODO "verify acronym casing"; `level: medium` on a rule that matches benign single reads | Stale marker; alert fatigue | Resolve TODO; single-read rule → `level: low`; the fingerprint rule → `level: high` |

**Recommended detection, the recon fingerprint.** This is an aggregation over distinct SES read APIs and belongs in a log platform (Query 3) or a Sigma **correlation**:

```yaml
# Document 1 - base rule: any SES read API (v1 + v2)
title: SES read API call
id: 9d1c4e77-3a52-4b8e-9f10-2c7a6b0d5e31
name: ses_read_base
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ses.amazonaws.com'   # SES v1 AND SESv2 both log under this source
    eventName:
      - 'GetAccountSendingEnabled'
      - 'GetSendQuota'
      - 'ListIdentities'
      - 'GetIdentityVerificationAttributes'
      - 'GetAccount'                   # SESv2 (sending-enabled + quota in one call)
      - 'ListEmailIdentities'          # SESv2
  condition: selection
level: low
---
# Document 2 - correlation: many DISTINCT SES read APIs from one principal
title: SES phishing-capability reconnaissance fingerprint
status: experimental
correlation:
  type: value_count
  rules:
    - ses_read_base
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gte: 3
    field: eventName                   # count DISTINCT SES read APIs
level: high
```

**On error strings (learned from prior techniques):** SES denials surface as `AccessDenied` / `AccessDeniedException` (not `Client.`-prefixed like EC2). Match both if you add a permission-probing rule, and confirm against a real event.

---

### Key Investigation Queries

> CloudTrail extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`, robust, unlike `--output text | jq`.

#### Query 1: Who ran the SES recon, and how complete was the fingerprint?

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '6 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-6H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

# Union the SES read events (v1 + v2) and group by principal
for EV in GetAccountSendingEnabled GetSendQuota ListIdentities \
          GetIdentityVerificationAttributes GetAccount ListEmailIdentities; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$START" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {arn: .userIdentity.arn, ev: .eventName, access_key: .userIdentity.accessKeyId,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.arn) | map({
      principal: .[0].arn,
      distinct_ses_reads: ([.[] | select(.error=="SUCCESS") | .ev] | unique),
      read_count: ([.[] | select(.error=="SUCCESS") | .ev] | unique | length),
      enumerated_identities: ([.[] | select(.ev | test("ListIdentities|ListEmailIdentities|GetIdentityVerification"))] | length > 0),
      access_keys: ([.[].access_key] | unique),   # feeds ACCESS_KEY_ID in Query 5
      denied: ([.[] | select(.error!="SUCCESS")] | length),
      source_ips: ([.[].ip] | unique)
    }) | sort_by(-.read_count)'
```

The suspect is the principal with `read_count ≥ 3` and `enumerated_identities:
true`, that is the full phishing-capability assessment.

#### Query 2: What did the recon reveal? (assess exposure)

The attacker now knows this. Reproduce it (read-only) so you know what they know.

```bash
REGION="us-east-1"

echo "=== Sending enabled? ==="
aws ses get-account-sending-enabled --region "$REGION"

echo "=== Send quota / rate ==="
aws ses get-send-quota --region "$REGION"

echo "=== Verified identities (potential spoof-from senders) ==="
aws ses list-identities --region "$REGION" --query 'Identities' --output text

echo "=== Which identities are verified/usable ==="
# get-identity-verification-attributes caps at 100 identities per call: batch it
# (as attack.py does) so accounts with >100 verified identities don't error out.
aws ses list-identities --region "$REGION" --query 'Identities' --output text | \
  tr '\t' '\n' | grep . | xargs -n 100 sh -c '
    aws ses get-identity-verification-attributes --identities "$@" \
      --region "'"$REGION"'" --query "VerificationAttributes"' _
```

A high quota + sending enabled + verified **production domains** = the account is
immediately usable for convincing phishing. That raises the incident's priority.

#### Query 3: Deployable fingerprint detection (log platform)

**Dialect: Sentinel / Azure Log Analytics KQL**, not CloudWatch Logs Insights. Counts distinct SES read APIs (v1 + v2) per principal per 10-minute window.

```kql
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventSource == "ses.amazonaws.com"   // v1 and v2 both log here
| where EventName in ("GetAccountSendingEnabled","GetSendQuota","ListIdentities",
                      "GetIdentityVerificationAttributes","GetAccount","ListEmailIdentities")
| where isempty(ErrorCode)
| summarize
    DistinctReads = dcount(EventName),
    ReadSet       = make_set(EventName, 10),
    IdentityEnum  = countif(EventName in ("ListIdentities","ListEmailIdentities","GetIdentityVerificationAttributes")),
    SourceIPs     = make_set(SourceIpAddress, 10),
    FirstSeen     = min(TimeGenerated),
    LastSeen      = max(TimeGenerated)
    by UserIdentityArn, bin(TimeGenerated, 10m)
| where DistinctReads >= 3 and IdentityEnum > 0
| extend Verdict = "SES PHISHING-CAPABILITY RECON - P0"
| order by DistinctReads desc
```

CloudWatch Logs Insights equivalent:

```
fields @timestamp, userIdentity.arn, eventName
| filter eventSource = "ses.amazonaws.com"
| filter eventName in ["GetAccountSendingEnabled","GetSendQuota","ListIdentities","GetIdentityVerificationAttributes","GetAccount","ListEmailIdentities"]
| filter not ispresent(errorCode)
| stats count_distinct(eventName) as distinct_reads by userIdentity.arn, bin(10m)
| filter distinct_reads >= 3
```

#### Query 4: Did recon turn into abuse? (the query that finds real damage)

Abuse shows up in **two different logs**, and the send events are the ones that
matter most, so read both, and do not trust the management-event query alone.

**Part A, control-plane abuse (CloudTrail management events).** Sandbox/quota
changes and new sender identities are management events and *are* in
`lookup-events`.

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
SUSPECT_ARN="<principal-arn-from-Query-1>"

for EV in UpdateAccountSendingEnabled PutAccountSendingAttributes \
          VerifyEmailIdentity VerifyDomainIdentity CreateEmailIdentity; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$START" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) |
    {time: .eventTime, event: .eventName,
     target: (.requestParameters.emailAddress // .requestParameters.domain
              // .requestParameters.emailIdentity // null),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

**Part B, the actual sends (NOT in `lookup-events`).** `ses:SendEmail`,
`SendRawEmail`, `SendTemplatedEmail`, `SendBulkTemplatedEmail` are **data-plane
events**. CloudTrail *Event History* (`lookup-events`) returns only management
events, so a `lookup-events` search for these **always returns zero, even during
an active spam run.** Read the send activity from where it actually lives:

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

# 1. CloudWatch SES metrics: a send spike is the fastest signal
aws cloudwatch get-metric-statistics --namespace AWS/SES \
  --metric-name Send --region "$REGION" \
  --start-time "$START" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 3600 --statistics Sum

# 2. If SES data-event logging is enabled on a trail (GA 2025), query that
#    trail's S3/CloudWatch Logs destination for Send* by the suspect principal.
# 3. If SES event publishing (to CloudWatch/SNS/Firehose) is configured, use that
#    destination for per-message detail.
```

A control-plane hit in Part A, **or** a send spike in Part B, means the recon
became active abuse, escalate and treat as an active phishing/spam incident. A
zero result from Part A alone is **not** evidence of no sending.

#### Query 5: Full session reconstruction

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

ACCESS_KEY_ID="<AKIA-or-ASIA-key-from-Query-1>"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$START" \
  --region us-east-1 --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'sort_by(.time)'
```

#### Query 6: Multi-region sweep (SES is regional)

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

for REGION in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text); do
  COUNT=$(aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ListIdentities \
    --start-time "$START" \
    --region "$REGION" --query 'length(Events)' --output text 2>/dev/null)
  [ -n "$COUNT" ] && [ "$COUNT" != "0" ] && [ "$COUNT" != "None" ] && \
    echo "[!] $REGION, $COUNT ListIdentities events (SES recon may span regions)"
done
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Reconnaissance itself is contained by stopping the principal; the graver risk is
recon becoming send-abuse. If Query 4 shows any sending or identity changes,
treat this as an active phishing incident and pause SES sending immediately.

> Run every containment/eradication command under the **break-glass responder
> credentials** from §1, not under any principal being contained.

#### Step 1: Disable the offending credential

```bash
SUSPECT_ARN="<principal-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  VICTIM_USER=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')      # user ARN: name = last segment
  aws iam list-access-keys --user-name "$VICTIM_USER" \
    --query 'AccessKeyMetadata[*].{KeyId:AccessKeyId,Status:Status}' --output table
  COMPROMISED_KEY_ID="<key-id>"
  aws iam update-access-key --user-name "$VICTIM_USER" \
    --access-key-id "$COMPROMISED_KEY_ID" --status Inactive
  echo "[OK] Disabled key $COMPROMISED_KEY_ID for $VICTIM_USER"
fi
```

#### Step 2: Revoke live STS sessions (assumed-role principals)

```bash
# assumed-role ARN - arn:aws:sts::<acct>:assumed-role/<RoleName>/<SessionName>
# Role name is the SECOND path segment, NOT $NF.
SUSPECT_ROLE=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')

aws iam put-role-policy \
  --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyRevokeSessions" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny", "Action": "*", "Resource": "*",
      "Condition": {"DateLessThan": {"aws:TokenIssueTime": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"}}
    }]
  }'
echo "[OK] Pre-existing sessions for $SUSPECT_ROLE revoked"
```

#### Step 3: Pause SES sending IF abuse is observed or imminent

Only if Query 4 shows sending/identity changes, or the account is high-risk
(production domains, high quota) and compromise is confirmed. This stops the
attack but also stops legitimate mail, a decision, not a reflex.

```bash
REGION="us-east-1"

# Account-wide kill switch for SES sending (v1)
aws ses update-account-sending-enabled --no-enabled --region "$REGION" && \
  echo "[OK] SES account sending DISABLED in $REGION (legitimate mail also paused)"

# Confirm
aws ses get-account-sending-enabled --region "$REGION"
```

A narrower alternative, if the abuse is confined to a specific identity or you
must keep other mail flowing: deny the send actions on the suspect principal
instead of the account-wide switch.

```bash
SUSPECT_ROLE="<role-name>"
aws iam put-role-policy --role-name "$SUSPECT_ROLE" \
  --policy-name "EmergencyDenySES" \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":["ses:SendEmail","ses:SendRawEmail","ses:SendBulkTemplatedEmail","ses:SendTemplatedEmail"],"Resource":"*"}]
  }'
echo "[OK] SES send actions denied for $SUSPECT_ROLE"
```

---

## 4. Eradication

### Remove Attacker Access

Reconnaissance creates nothing to delete. Eradication is: remove any
attacker-added sending identities, right-size SES permissions, and confirm the
account's mail integrity.

#### Remove attacker-added SES identities

If Query 4 showed identity creation, the attacker added a sender they control.
Remove it.

```bash
REGION="us-east-1"

# List identities and compare against the known-good inventory from §1
aws ses list-identities --region "$REGION" --query 'Identities' --output text

# Delete an attacker-added identity (v1)
ATTACKER_IDENTITY="<attacker-added-domain-or-address>"
aws ses delete-identity --identity "$ATTACKER_IDENTITY" --region "$REGION" && \
  echo "[OK] Deleted attacker identity $ATTACKER_IDENTITY"
```

#### Right-size SES permissions

```bash
SUSPECT_ROLE="<role-name>"

# Which policies grant SES to this principal
aws iam list-attached-role-policies --role-name "$SUSPECT_ROLE" --output table
aws iam list-role-policies --role-name "$SUSPECT_ROLE" --output table

# Scope SES to only what the workload needs. Most principals need no SES at all;
# a sender needs ses:SendEmail on specific verified identities, nothing more.
# Remove any grant of ses:* or SES read APIs from principals that don't send mail.
```

#### Assess reputation / blocklist impact if sending occurred

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"

# Bounce and complaint rates: a spam run spikes these and threatens the account's
# SES reputation (and can trigger AWS sending pause)
aws ses get-account-sending-enabled --region "$REGION"
aws cloudwatch get-metric-statistics --namespace AWS/SES \
  --metric-name Reputation.BounceRate --region "$REGION" \
  --start-time "$START" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --period 3600 --statistics Maximum 2>/dev/null
```

If a spam/phishing run occurred, engage AWS Support about sender reputation and
notify recipients/security contacts as your IR policy requires.

#### Remove emergency policies once clean

```bash
SUSPECT_ROLE="<role-name>"
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyDenySES" 2>/dev/null
aws iam delete-role-policy --role-name "$SUSPECT_ROLE" --policy-name "EmergencyRevokeSessions" 2>/dev/null
echo "[OK] Emergency policies removed"
```

---

## 5. Recovery

### Restore Clean State

#### Re-enable SES sending (if it was paused)

```bash
REGION="us-east-1"
# Only after: principal contained, attacker identities removed, permissions scoped
aws ses update-account-sending-enabled --enabled --region "$REGION" && \
  echo "[OK] SES account sending re-enabled in $REGION"
aws ses get-account-sending-enabled --region "$REGION"
```

#### Verify the identity list matches the known-good inventory

```bash
REGION="us-east-1"
CURRENT=$(aws ses list-identities --region "$REGION" --query 'Identities' --output text | tr '\t' '\n' | sort)
# Compare against ./known-good-identities.txt (your §1 inventory)
if diff <(echo "$CURRENT") <(sort ./known-good-identities.txt) >/dev/null 2>&1; then
  echo "[OK] SES identity list matches known-good inventory"
else
  echo "[FAIL] SES identity list differs from known-good, review:"
  diff <(echo "$CURRENT") <(sort ./known-good-identities.txt)
fi
```

#### Verify no further SES recon since containment

Recon and identity/config changes are management events and are checkable here.
For *sending*, check CloudWatch `AWS/SES` `Send` (data-plane; not in
`lookup-events`), a flat post-containment `Send` metric is the real "no further
abuse" evidence.

```bash
REGION="us-east-1"
SUSPECT_ARN="<principal-arn>"
CONTAINED_AT="<iso8601-containment-timestamp>"

# Management-event recon/config activity by the suspect since containment
COUNT=$(for EV in ListIdentities GetIdentityVerificationAttributes GetAccount \
                  ListEmailIdentities UpdateAccountSendingEnabled CreateEmailIdentity; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$CONTAINED_AT" --region "$REGION" --output json 2>/dev/null
done | \
  jq -r --arg arn "$SUSPECT_ARN" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | select(.errorCode == null) | .eventTime' | grep -c .)

[ "$COUNT" -eq 0 ] && echo "[OK] No further SES management activity from $SUSPECT_ARN since containment" \
                   || echo "[FAIL] $COUNT further SES management calls, containment did not hold"

# Sends are data-plane: confirm the Send metric is flat since containment
echo "Also confirm AWS/SES 'Send' (Sum) is ~0 since $CONTAINED_AT:"
aws cloudwatch get-metric-statistics --namespace AWS/SES --metric-name Send \
  --region "$REGION" --start-time "$CONTAINED_AT" \
  --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --period 3600 --statistics Sum
```

#### Verify the credential is dead

```bash
SUSPECT_ARN="<principal-arn>"
if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')
  ACTIVE=$(aws iam list-access-keys --user-name "$U" \
    --query 'AccessKeyMetadata[?Status==`Active`]' --output text)
  [ -z "$ACTIVE" ] && echo "[OK] No active keys for $U" || echo "[FAIL] $U still has active keys"
fi
```

#### Confirm the corrected detection fires

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '30 minutes ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-30M +%Y-%m-%dT%H:%M:%SZ)

REGION="us-east-1"
TEST_PRINCIPAL="<arn-used-for-the-emulation-run>"

READS=$(for EV in GetAccountSendingEnabled GetSendQuota ListIdentities GetIdentityVerificationAttributes; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$EV \
    --start-time "$START" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -r --arg arn "$TEST_PRINCIPAL" '.Events[].CloudTrailEvent | fromjson |
    select(.userIdentity.arn == $arn) | .eventName' | sort -u | grep -c .)

echo "Distinct SES read APIs by the test principal: $READS"
[ "$READS" -ge 3 ] && echo "[OK] Fingerprint present (>=3 distinct SES reads), the correlation rule has data to fire on" \
                   || echo "[FAIL] Expected >=3 distinct SES reads; saw $READS, trail may be WriteOnly/delayed"
echo "Confirm the deployed rule produced ONE fingerprint alert, not one per SES read."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could enumerate SES sending capability | SES read APIs granted to a principal with no operational need; no allowlist of SES readers |
| Reconnaissance undetected | Shipped rule fired on single benign reads and had no fingerprint (distinct-API) threshold; no SESv2 coverage |
| The account was attractive to abuse | Sending enabled with a high quota and verified production domains, reachable by a broadly-permissioned principal |
| Recon-to-abuse transition unalerted | No follow-on detection for send spikes, sandbox-exit, or new-identity creation |

### Recommended Guardrails

**Restrict SES to principals that actually send mail**

```json
// Deny all SES to principals outside the mail-sending / ops allowlist
{
  "Effect": "Deny",
  "Action": "ses:*",
  "Resource": "*",
  "Condition": {
    "StringNotLike": {
      "aws:PrincipalArn": [
        "arn:aws:iam::*:role/mail-sender",
        "arn:aws:iam::*:role/ses-ops",
        "arn:aws:iam::*:role/BreakGlassAdmin"
      ]
    }
  }
}
```

**Scope senders to their own identities**
- A sending role should hold `ses:SendEmail`/`SendRawEmail` conditioned on `ses:FromAddress` / a specific verified identity ARN, not `ses:*` on `Resource: *`
- Keep the account in the SES **sandbox** unless production sending is genuinely required; sandbox caps blast radius even if a principal is compromised

**Protect sender reputation**
- Configure SES bounce/complaint alarms and a low-threshold send-rate anomaly alert, these catch abuse fast and protect the account from AWS-imposed sending pauses and external blocklisting

**Detection improvements**
- Deploy the fingerprint rule (Query 3): ≥3 distinct SES read APIs (v1 + v2) per principal per window, weighting identity enumeration, never a single-read match
- Add follow-on rules: `SendEmail`/`SendRawEmail` spikes, `UpdateAccountSendingEnabled`, and new-identity creation by non-ops principals
- Maintain the SES-reader allowlist and alert any SES read outside it

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1087 (as mapped by Stratus), see caveat below |
| MITRE tactic | Discovery (TA0007) |
| Primary APIs (v1) | `ses:GetAccountSendingEnabled`, `ses:GetSendQuota`, `ses:ListIdentities`, `ses:GetIdentityVerificationAttributes` |
| SESv2 equivalents (evasion coverage) | `GetAccount` (sending-enabled + quota), `ListEmailIdentities` |
| Event source | `ses.amazonaws.com`, both SES v1 and SESv2 log here (there is no `email.amazonaws.com` CloudTrail source) |
| Key detection insight | The signal is the *fingerprint*, ≥3 distinct SES read APIs from one principal including identity enumeration, not any single call. Cover v1 **and** v2 names |
| Error strings (not `Client.`-prefixed) | `AccessDenied` / `AccessDeniedException` |
| Resources created | None, read-only reconnaissance |
| Follow-on to watch for | `ses:SendEmail`/`SendRawEmail`/`SendBulkTemplatedEmail` spikes, `UpdateAccountSendingEnabled` / sandbox-exit, new identity verification |

**MITRE mapping caveat:** the MANIFEST maps this to **T1087 (Account Discovery)**,
which describes enumerating *user/account* identities, a poor fit for probing an
email-sending service. **T1526 (Cloud Service Discovery)** is the closer match
(enumerating available cloud services and their configuration). The mapping is
inherited from Stratus Red Team; treat the tactic (Discovery) as authoritative
and the technique ID as approximate. Recorded for the end-of-run MITRE-mapping
finding.

### Revert

The emulation creates no infrastructure, `pulumi destroy` is effectively a
no-op. The technique is read-only and leaves no artifacts to clean after an
emulation run. After a **real** incident, the "revert" is the §4 work: remove any
attacker-added sending identities, scope SES permissions, and, if a spam/phishing
run occurred, remediate sender reputation. The knowledge the attacker gained
about your sending capability cannot be un-learned; least-privilege and
send-abuse alerting are the durable defenses.
