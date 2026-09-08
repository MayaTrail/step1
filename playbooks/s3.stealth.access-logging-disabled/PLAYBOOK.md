# IR Playbook: S3 Server Access Logging Silenced — `PutBucketLogging` used to disable or redirect delivery

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defence evasion — request-level visibility on a bucket is removed, either by turning server access logging off or by pointing it at a destination nobody reads |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Medium on its own, high when it precedes a change to the same bucket. AWS documents server access logs as best-effort and "not meant to be a complete accounting of all requests", so this is a visibility reduction rather than the destruction of an audit record — CloudTrail data events are the authoritative record and this call does not touch them. |
| MITRE Tactics | Defense Evasion |
| MITRE Techniques | T1685.002 |
| Services in Scope | S3, CloudTrail, CloudWatch Logs, IAM |

**What the technique does:** the actor calls `PutBucketLogging` on a bucket in one of two shapes.
With an **empty `BucketLoggingStatus`** logging is switched off — AWS: *"To enable logging, you use
`LoggingEnabled` and its children request elements. To disable logging, you use an empty
`BucketLoggingStatus` request element."* With **`LoggingEnabled` kept but `TargetBucket` or
`TargetPrefix` changed**, logging still reads as enabled while the records land somewhere nobody
queries. Both end the flow into the defender's pipeline; only the first looks like a disable.

**Why the usual reflexes miss it.** The first is to test only for the absence of `LoggingEnabled`,
which catches the disable and misses the redirect entirely. The second is to rate this as audit-log
destruction: these logs are explicitly best-effort, and treating their loss as evidence destruction
both overstates the incident and distracts from the record that does matter. The third is to confirm
the incident, or the recovery, by whether logs are arriving — AWS states that *"changes to the
logging status of a bucket take time to actually affect the delivery of log files"*, so arrival lags
the configuration by roughly an hour in both directions.

**Detection thesis:** cover both shapes of the call, rate the act itself at medium, and let the
**order** carry the weight — visibility reduced and *then* the bucket changed is the sequence worth
waking someone for.

**Adjacent playbooks.** The bucket exposure that often follows is
`../s3.exfiltration.bucket-policy-made-public/` and `../s3.exfiltration.public-access-block-removed/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. `PutBucketLogging` is a bucket-level call and
therefore a management event, on by default — this playbook's own signal does not need to be
purchased.

CloudTrail **data events** for buckets holding sensitive data. This is the point that makes the
severity call defensible: data events are the authoritative record of object access, they are
unaffected by `PutBucketLogging`, and they are what you fall back on when access logging goes dark.
They are off by default, billable, and cannot be enabled retroactively.

A record of which buckets deliver server access logs and **where** — the target bucket and prefix
for each. Without it the redirect rule cannot function, because "an unrecognised destination" has no
meaning until the recognised ones are written down.

Awareness that server access logs can also be delivered to **CloudWatch Logs**, configured through
the CloudWatch Logs APIs rather than through `PutBucketLogging`. Nothing in this playbook sees a
change made on that path. If your estate uses it, that path needs its own coverage.

**Alerting (must be pre-configured)**

- **Access logging disabled or redirected, then the same principal writes that bucket's policy or ACL within 1h → P0**
- **Access logging disabled or redirected, then Block Public Access weakened on the same bucket by the same principal → P0**
- **`PutBucketLogging` keeps `LoggingEnabled` but points `TargetBucket` at a destination not on the recorded list → P1**

**Response Tooling**

An IAM principal that can call `s3api put-bucket-logging` and `s3api get-bucket-logging` outside the
change pipeline, and read access to the log destination bucket.

Athena or CloudWatch Logs Insights already pointed at the access-log destination. Reconstructing
what the bucket served during the dark window means querying logs that arrived *before* it, and
setting that query up during the incident wastes the window.

**Known IOC Baselines**

The recorded log destinations, per bucket — target bucket and target prefix. These populate
`known_log_destinations` in the shipped rules; deployed empty, the redirect rule fires on every
logging configuration in the account.

The roles that own bucket lifecycle, populating `known_provisioners`. Every infrastructure apply
that rebuilds a bucket rewrites its logging configuration.

The buckets for which CloudTrail data events are enabled. During an incident this is the difference
between "we cannot say what was read" and "we can".

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | Access logging disabled or redirected, then `PutBucketPolicy` or `PutBucketAcl` on the same bucket by the same principal within the hour | Correlation rule | T1685.002 |
| P0 | Access logging disabled or redirected, then Block Public Access weakened on the same bucket by the same principal | Correlation rule | T1685.002 |
| P1 | `PutBucketLogging` keeps `LoggingEnabled` but points `TargetBucket` at a destination not on the recorded list — logging still reads as enabled | CloudTrail | T1685.002 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `PutBucketLogging` with an empty `BucketLoggingStatus` by a principal that is not a recorded provisioner | CloudTrail | T1685.002 |
| P2 | Logging disabled and the bucket also changed, but the bucket change came first — usually a rebuild | CloudTrail | T1685.002 |
| P2 | `TargetPrefix` changed while `TargetBucket` stays the same — records still delivered, under a prefix nothing ingests | CloudTrail | T1685.002 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Matches `putbucketlogging`, lowercased | CloudTrail emits `PutBucketLogging`. Whether the rule fires becomes a property of the index mapping — a keyword field never matches it, a lowercase-analysed text field does. A detection whose correctness depends on someone else's analyser is not one | Match the documented casing. Sigma is exact-match, so this is closed rather than hedged |
| Tests only for the absence of `LoggingEnabled` | That is AWS's documented disable and the logic is right, but a call that keeps `LoggingEnabled` and changes `TargetBucket` or `TargetPrefix` silences the pipeline just as completely while still reading as enabled. The stealthier shape is the invisible one | A second rule for the redirect case, gated on a populated list of recognised log destinations |
| Rated P2 as though an audit record were lost | AWS: server access logs are best-effort, *"might not be delivered at all"*, and *"not meant to be a complete accounting of all requests"*. CloudTrail data events are the authoritative record and this call does not touch them. Rating the act itself high inverts what actually matters | Medium for the act; the ordered pair — visibility reduced, then the bucket changed — carries the high |
| No principal filter | Every infrastructure apply that rebuilds a bucket rewrites its logging configuration, so an unfiltered rule fires on routine deploys | `known_provisioners` on both bucket rules, shipped with placeholders that must be populated |
| No coverage of the CloudWatch Logs delivery path | Server access logs can be delivered to CloudWatch Logs, configured outside `PutBucketLogging` entirely. A change there produces no S3 event | Not closable from S3 CloudTrail events. Stated as a named gap in §6 rather than papered over |
| MITRE: none | The pack maps this rule to nothing at all | `T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log`. |

**Recommended detection — both shapes of the call, and the sequence that matters.**

```yaml
# S3 server access logging disabled or redirected (T1685.002)
#
# DISABLING IS ONLY THE LOUD HALF. AWS: "To disable logging, you use an empty BucketLoggingStatus
# request element." The source rule tests exactly that and is right — but a call that KEEPS
# LoggingEnabled and changes TargetBucket or TargetPrefix silences the pipeline just as completely
# while still reading as enabled, and is invisible to it.
#
# Medium, not high, on AWS's own statement that these logs are best-effort and "not meant to be a
# complete accounting of all requests". CloudTrail data events are the authoritative record and this
# call does not touch them. Full rationale: detections/detection_note_t1685_002.md.
title: S3 server access logging disabled on a bucket
id: 4a1f3c62-9e8d-4b07-a5d1-7c206e94f81b
name: s3_access_logging_disabled
status: experimental
description: >-
  PutBucketLogging succeeded with an empty BucketLoggingStatus — AWS's documented way of turning
  server access logging off. Nothing is exposed and no authoritative record is lost, but request-level
  visibility on this bucket is now reduced, and the interesting question is what the same principal
  does with the bucket next.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.html
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName: 'PutBucketLogging'
  success:
    errorCode: null
  # BucketLoggingStatus is Required: Yes and LoggingEnabled is Required: No, so an absent
  # LoggingEnabled is the disable case and is the only thing that distinguishes it from a
  # reconfiguration.
  logging_off:
    requestParameters.BucketLoggingStatus.LoggingEnabled: null
  # POPULATE BEFORE DEPLOYING with the roles that own bucket lifecycle.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and logging_off and not known_provisioners
falsepositives:
  - >-
    A bucket being decommissioned, where logging is turned off as part of teardown. The bucket
    deletion that follows within the hour is the corroborating evidence.
  - >-
    A migration to CloudWatch Logs delivery, which is configured elsewhere and legitimately leaves
    this call looking like a disable. Confirm against the CloudWatch Logs delivery configuration
    rather than assuming either way.
level: medium
---
title: S3 server access logging redirected to an unrecognised destination
id: c8b504e7-2a36-4f91-8d0c-b3e75619af24
name: s3_access_logging_redirected
status: experimental
description: >-
  PutBucketLogging succeeded with LoggingEnabled still present but pointing at a TargetBucket that
  is not a recorded log destination. Logging still reads as enabled, so a rule testing only for the
  disable case sees nothing, while the log pipeline that anyone actually queries goes dry. AWS
  constrains the destination to the same account and Region, so this is not an exfiltration path —
  it is a way to make the logs land where nobody is looking.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html
  - https://attack.mitre.org/techniques/T1685/002/
tags:
  - attack.defense-evasion
  - attack.t1685.002
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName: 'PutBucketLogging'
  success:
    errorCode: null
  logging_on:
    requestParameters.BucketLoggingStatus.LoggingEnabled|exists: true
  # POPULATE BEFORE DEPLOYING with the buckets that legitimately receive access logs. Deployed
  # empty this fires on every logging configuration in the account.
  known_log_destinations:
    requestParameters.BucketLoggingStatus.LoggingEnabled.TargetBucket:
      - 'org-access-logs'
      - 'org-access-logs-archive'
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and logging_on and not known_log_destinations and not known_provisioners
falsepositives:
  - >-
    A new log destination bucket that has not been added to the list. That is the list being wrong
    rather than the rule, and the fix is to add it — widening the rule removes the only thing it
    checks.
level: medium
---
title: S3 access logging silenced and the bucket then reconfigured
id: 7d3e91b8-5c40-4a6f-b21e-08fa76d5c3e9
status: experimental
description: >-
  Access logging was disabled or redirected on a bucket and the same principal then changed that
  bucket's policy or ACL. Either half alone is ordinary; the order is the signal, because it is the
  order in which someone reduces visibility before acting rather than after. The reverse order is a
  bucket being tidied up post-change.
references:
  - https://attack.mitre.org/techniques/T1685/002/
  - https://attack.mitre.org/techniques/T1530/
tags:
  - attack.defense-evasion
  - attack.collection
  - attack.t1685.002
  - attack.t1530
correlation:
  type: temporal_ordered
  rules:
    - s3_access_logging_disabled
    - s3_bucket_open_write
  group-by:
    - userIdentity.arn
  timespan: 1h
falsepositives:
  - >-
    An infrastructure apply that rebuilds a bucket from scratch and legitimately rewrites logging
    and policy in one run. Allowlist the provisioning role on the base rules rather than widening
    the timespan.
level: high
---
title: S3 bucket policy or ACL written
id: 1e6a48d3-70bf-4c25-9a83-df2015b7e64c
name: s3_bucket_open_write
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. Any successful write to a
  bucket's policy or ACL, including ordinary infrastructure applies.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName:
      - 'PutBucketPolicy'
      - 'PutBucketAcl'
  success:
    errorCode: null
  condition: selection and success
level: informational
```

What this set structurally cannot do: it cannot tell you what the bucket served during the dark
window, because those records were never delivered; and it cannot see a logging change made through
the CloudWatch Logs delivery path, which is configured outside `PutBucketLogging` entirely.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

Run Query 1 first; it produces the principal and bucket the rest take as input.

#### Query 1 — Reconstruct: disable or redirect, and what the principal did around it

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in PutBucketLogging PutBucketPolicy PutBucketAcl PutBucketPublicAccessBlock; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | .requestParameters as $rp
      | ($rp.BucketLoggingStatus.LoggingEnabled // null) as $le
      # AWS: "To disable logging, you use an empty BucketLoggingStatus request element." So on a
      # PutBucketLogging an absent LoggingEnabled IS the disable, and is the only thing separating
      # it from a reconfiguration. Any other event here is context for the ordering.
      | (if .eventName != "PutBucketLogging" then "context"
         elif $le == null then "LOGGING-OFF"
         else "logging-> \($le.TargetBucket)/\($le.TargetPrefix // "")" end) as $what
      | "\(.eventTime)  \(.eventName)  \(.userIdentity.arn)  \($what)  " +
        "bucket=\($rp.bucketName // "-")  ip=\(.sourceIPAddress)"'
done | sort
```

Sorted by time on purpose. The finding is not the logging change, it is whether the logging change
came **before** the other events on that bucket. `LOGGING-OFF` followed by a policy write is the P0;
the reverse order is usually a rebuild.

#### Query 2 — Sweep: the live logging configuration of every bucket

```bash
# POPULATE with this account's real log destinations before running.
KNOWN_DESTS="org-access-logs org-access-logs-archive"

aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n' \
| while read -r B; do
    [ -z "$B" ] && continue
    CFG="$(aws s3api get-bucket-logging --bucket "$B" --output json 2>/dev/null)"
    TB="$(printf '%s' "$CFG" | jq -r '.LoggingEnabled.TargetBucket // ""')"
    TP="$(printf '%s' "$CFG" | jq -r '.LoggingEnabled.TargetPrefix // ""')"
    if [ -z "$TB" ]; then
      echo "[!] $B — server access logging OFF"
      continue
    fi
    MATCH=0
    for D in $KNOWN_DESTS; do [ "$TB" = "$D" ] && MATCH=1; done
    if [ "$MATCH" -eq 1 ]; then
      echo "[OK] $B -> $TB/$TP"
    else
      echo "[!] $B -> $TB/$TP — destination not on the recorded list"
    fi
  done
```

An `OFF` row is not automatically a finding — plenty of buckets never had logging. Compare against
the §1 record of which buckets are supposed to deliver logs; a bucket that was on that list and now
reads `OFF` is the finding, and the one that never was is a gap of a different kind.

#### Query 3 — Corroborate: is the authoritative record still intact

```bash
BUCKET="${1:?bucket name from Query 1 required}"
REGION="${AWS_REGION:-us-east-1}"

echo "=== Does any trail record data events for this bucket? ==="
aws cloudtrail list-trails --region "$REGION" --query 'Trails[].TrailARN' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r T; do
    [ -z "$T" ] && continue
    aws cloudtrail get-event-selectors --trail-name "$T" --region "$REGION" --output json 2>/dev/null \
    | jq -r --arg t "$T" 'if (tostring | test("AWS::S3::Object"))
                          then "[OK] \($t) records S3 object data events" else empty end'
  done

echo
echo "[!] If an [OK] printed, object access during the dark window IS still recorded — CloudTrail"
echo "    data events are unaffected by PutBucketLogging and are the authoritative record."
echo "[!] If nothing printed, neither source covers the window and the honest finding is 'unknown'."
```

This query decides how the incident is written up. Server access logs are best-effort by AWS's own
statement; data events are not. If data events cover this bucket, losing access logs is a
housekeeping problem. If they do not, the dark window is genuinely dark.

#### Query 4 — Full session reconstruction of the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 1 required}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

# For an assumed role the CloudTrail username is the SESSION name: the second slash-separated
# segment after `assumed-role/`, not the role name and not the last segment.
case "$PRINCIPAL" in
  *:assumed-role/*) LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $2}')" ;;
  *)                LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')" ;;
esac

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue="$LOOKUP" \
  --start-time "$START" --region "$REGION" --max-results 200 \
  --query 'Events[].[EventTime,EventName,EventSource]' --output text 2>/dev/null | sort
```

A provisioning role rewriting logging alongside twenty other bucket-configuration calls in one
minute is a deploy. A principal whose only S3 calls that week are `GetBucketLogging` and then
`PutBucketLogging` is not.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restoring logging is quick and low-risk, so it goes first — but understand that it does not restore
the missing window and does not take effect immediately. The real containment work is Step 3.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 1 shows the logging change came **before** a policy, ACL or Block Public
Access change on the same bucket, treat this as the exposure playbook rather than this one — go to
`../s3.exfiltration.bucket-policy-made-public/` or
`../s3.exfiltration.public-access-block-removed/` and contain the exposure first. Logging can be
restored afterwards; an open bucket cannot wait.

#### Step 1 — Restore logging to the recorded destination

```bash
BUCKET="${1:?bucket name required}"
TARGET_BUCKET="${2:?recorded log destination bucket required}"
TARGET_PREFIX="${3:-${BUCKET}/}"

# Preserve whatever is configured now, before overwriting it — the attacker's destination is
# evidence, and it is the only place the redirected records exist.
aws s3api get-bucket-logging --bucket "$BUCKET" --output json 2>/dev/null \
  | tee "/tmp/${BUCKET}-logging-before.json"

if aws s3api head-bucket --bucket "$TARGET_BUCKET" >/dev/null 2>&1; then
  aws s3api put-bucket-logging --bucket "$BUCKET" --bucket-logging-status "$(jq -n \
      --arg tb "$TARGET_BUCKET" --arg tp "$TARGET_PREFIX" \
      '{LoggingEnabled: {TargetBucket: $tb, TargetPrefix: $tp}}')" \
    && echo "[OK] logging restored on $BUCKET -> $TARGET_BUCKET/$TARGET_PREFIX"
else
  echo "[FAIL] target bucket $TARGET_BUCKET not found — AWS requires it in the same account and Region"
fi
```

AWS constrains the destination: *"The destination bucket must be in the same AWS Region and AWS
account as the source bucket."* If the recorded destination fails that check, the record is wrong
rather than the command.

#### Step 2 — Verify from configuration, never from log arrival

```bash
BUCKET="${1:?bucket name required}"

aws s3api get-bucket-logging --bucket "$BUCKET" --output json 2>/dev/null \
| jq -r 'if .LoggingEnabled == null
         then "[FAIL] logging is still OFF"
         else "[OK] logging -> \(.LoggingEnabled.TargetBucket)/\(.LoggingEnabled.TargetPrefix // "")"
         end'
```

Do not confirm this by watching for log objects to appear. AWS: *"Changes to the logging status of a
bucket take time to actually affect the delivery of log files... if you enable logging for a bucket,
some requests made in the following hour might be logged, and others might not."* Records will also
keep arriving at the **old** destination for around an hour after the change. Both directions lag,
so arrival is evidence of nothing for the first hour and `get-bucket-logging` is the only truth.

#### Step 3 — Contain the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 1 required}"

case "$PRINCIPAL" in
  *:user/*)
    U="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')"
    aws iam list-access-keys --user-name "$U" --query 'AccessKeyMetadata[].AccessKeyId' \
      --output text 2>/dev/null | tr '\t' '\n' | while read -r K; do
        [ -z "$K" ] && continue
        aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive \
          && echo "[OK] key $K deactivated"
      done
    ;;
  *:assumed-role/*)
    # Role name is the FIRST segment after `assumed-role/`; the second is the session name.
    R="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $1}')"
    echo "[!] assumed role: $R — existing session credentials remain valid until expiry."
    echo "    Revoking the role's permissions does not recall tokens already issued. Save as"
    echo "    revoke.json and attach with put-role-policy:"
    cat <<JSON
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*",
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"}}}]}
JSON
    ;;
  *) echo "[!] unrecognised principal shape: $PRINCIPAL — contain manually" ;;
esac
```

The assumed-role branch prints rather than applies: an inline deny on a shared automation role can
halt a deployment pipeline, and whether that is acceptable is not a call the script can make.

#### Step 4 — Preserve the records that do exist, including the redirected ones

```bash
BUCKET="${1:?source bucket required}"
OLD_TARGET="$(jq -r '.LoggingEnabled.TargetBucket // ""' "/tmp/${BUCKET}-logging-before.json" 2>/dev/null)"
OLD_PREFIX="$(jq -r '.LoggingEnabled.TargetPrefix // ""' "/tmp/${BUCKET}-logging-before.json" 2>/dev/null)"

if [ -n "$OLD_TARGET" ]; then
  echo "[!] records were being delivered to $OLD_TARGET/$OLD_PREFIX — copy before anything ages out"
  aws s3 sync "s3://${OLD_TARGET}/${OLD_PREFIX}" "./evidence-${BUCKET}-redirected/" \
    && echo "[OK] redirected records preserved"
else
  echo "(logging was off, not redirected — no alternate destination to collect from)"
fi

# Records delivered up to ~1h after the change landed at the OLD destination, so the boundary of
# the dark window is fuzzy in that direction and the last hour before it is the most valuable.
echo "[!] Also preserve the recorded destination's objects around the change window."
```

---

## 4. Eradication

### Remove Attacker Access

#### Decide what the dark window actually cost

Query 3 answers this and the answer is binary. If CloudTrail data events cover the bucket, object
access during the window **is** recorded, the authoritative record is intact, and losing access logs
is a housekeeping problem rather than an evidence problem. If they do not, neither source covers the
window and the honest finding is *unknown* — say that rather than "no evidence of access", which
reads as a negative result when it is an absent one.

Note that the boundary is soft in both directions. AWS states logging changes *"take time to
actually affect the delivery of log files"*, so some records from the first hour of the window
exist, and some records from the hour before the change may never have been delivered at all.

#### Close every other bucket the sweep found

Query 2 rarely finds only one. A principal that could rewrite logging on one bucket usually could
everywhere, and the sweep also surfaces buckets that quietly lost logging months ago. Separate the
two: recent changes are incident scope, pre-existing gaps are a hygiene backlog.

#### Restrict who can change logging configuration

`s3:PutBucketLogging` belongs to infrastructure automation. Review every identity and resource
policy granting it, and every wildcard (`s3:Put*`, `s3:*`) that grants it by accident. Then deny it
outright outside a break-glass path:

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyLoggingConfigChanges",
  "Effect": "Deny",
  "Action": ["s3:PutBucketLogging"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourProvisioningRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone including the pipeline that legitimately needs it. Test in a non-production OU first.

#### Cover the delivery path this playbook cannot see

If any bucket in the estate delivers server access logs to CloudWatch Logs, that configuration lives
behind the CloudWatch Logs APIs and produces no S3 event. It needs its own detection on the
CloudWatch Logs delivery calls, and this playbook does not provide it.

---

## 5. Recovery

### Restore Clean State

#### Verify every bucket is logging where it should

Re-run **§2 Query 2**: recovery is verified when every bucket that is supposed to deliver logs
reports `[OK]` against a recorded destination. Then confirm the specific bucket's configuration
directly:

```bash
BUCKET="${1:?bucket name required}"
EXPECT_TARGET="${2:?expected destination bucket required}"

aws s3api get-bucket-logging --bucket "$BUCKET" --output json 2>/dev/null \
| jq -r --arg e "$EXPECT_TARGET" '
    if .LoggingEnabled == null then "[FAIL] logging OFF"
    elif .LoggingEnabled.TargetBucket != $e then "[FAIL] delivering to \(.LoggingEnabled.TargetBucket), expected \($e)"
    else "[OK] \(.LoggingEnabled.TargetBucket)/\(.LoggingEnabled.TargetPrefix // "")"
    end'
```

#### Confirm delivery has actually resumed — after the lag, not during it

```bash
TARGET_BUCKET="${1:?log destination bucket required}"
TARGET_PREFIX="${2:?log prefix required}"

# AWS: changes to logging status "take time to actually affect the delivery of log files", and
# records arrive "within a few hours". Checking sooner than this proves nothing either way.
echo "[!] Run this NO EARLIER than 3 hours after Step 1, or the result is meaningless."
aws s3 ls "s3://${TARGET_BUCKET}/${TARGET_PREFIX}" --recursive 2>/dev/null \
  | tail -5 || echo "[FAIL] cannot list the destination prefix"
```

This is the one check that genuinely takes hours, and running it early is the most common way a
responder wrongly concludes the fix did not work. The configuration check above is the real gate.

#### Confirm the corrected detection fires

```bash
BUCKET="${1:?disposable test bucket required — do NOT use a production bucket}"
DEST="${2:?a bucket NOT on the recorded destination list}"

# Exercise the REDIRECT shape, not the disable: it is the half the source rule could not see, so it
# is the half worth proving. Logging stays enabled throughout, so nothing goes dark.
aws s3api put-bucket-logging --bucket "$BUCKET" --bucket-logging-status "$(jq -n --arg d "$DEST" \
    '{LoggingEnabled: {TargetBucket: $d, TargetPrefix: "detection-test/"}}')" \
  && echo "[OK] logging redirected — expect the redirect rule within 15 min"

sleep 60
aws s3api put-bucket-logging --bucket "$BUCKET" --bucket-logging-status '{}' \
  && echo "[OK] reverted to no logging on the scratch bucket"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Did the logging change come before or after the other changes to that bucket? | The order is the entire finding. Before is a P0; after is usually a rebuild. |
| Was it a disable or a redirect? | A redirect leaves logging reading as enabled and would have been invisible to the original rule — if it was a redirect, the coverage gap is the more important finding. |
| Were CloudTrail data events enabled for this bucket? | Decides whether the dark window is genuinely dark or merely inconvenient, and that was settled months ago. |
| How did the principal hold `s3:PutBucketLogging`? | Usually via an `s3:*` or `s3:Put*` wildcard that nobody intended to include it. |
| Was the destination a real log bucket that nobody queries, or a new one? | An unqueried real bucket is the harder case — it passes a configuration review and still delivers nothing useful. |
| Does any bucket here deliver to CloudWatch Logs? | If so, an entire delivery path is outside this playbook's coverage and needs its own. |

### Recommended Guardrails

**Alert on the sequence, not the act.** Access logging changes are common in an IaC estate and rating
each one highly trains responders to close them. What is rare, and worth waking someone for, is
visibility being reduced on a bucket immediately before that bucket is changed.

**Record the log destinations, per bucket, as data.** The redirect rule is inert without it, and the
redirect is the shape the original rule could not see. This is the single highest-value item in §1.

**Enable CloudTrail data events on buckets holding regulated data.** It is what makes losing access
logs survivable, and it cannot be decided retroactively.

**Deny `s3:PutBucketLogging` outside the provisioning path** with the SCP fragment in §4, so a
compromised application role cannot change it at all.

**Monitor the configuration, not the log flow.** AWS Config's `s3-bucket-logging-enabled` reports
state; log arrival lags configuration by hours in both directions and will mislead anyone using it
as a health signal.

### Technique Reference

**T1685.002 — Disable or Modify Tools: Disable or Modify Cloud Log.** Verified live at
https://attack.mitre.org/techniques/T1685/002/ on 2026-08-30.

The source rule carried **no** MITRE mapping.

AWS references relied on throughout, all verified 2026-08-30:

- `PutBucketLogging` API reference — the empty-`BucketLoggingStatus` disable, and
  `LoggingEnabled` being `Required: No`:
  https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.html
- Server access logging overview — best-effort delivery, the CloudWatch Logs delivery path, the
  same-account/same-Region constraint, and the delay before a status change takes effect:
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html

Service-wide verified behaviour shared by every `s3.*` playbook is in `../_ground-truth/s3.md`.

### Residual Risk

**The CloudWatch Logs delivery path is not covered.** Server access logs delivered to CloudWatch
Logs are configured through the CloudWatch Logs APIs, produce no S3 event, and are invisible to
every rule in this directory. This is the largest gap and it is not closable from S3 CloudTrail
events — it needs detection on the delivery configuration calls themselves.

**A redirect to a real but unqueried log bucket passes review.** The rule catches destinations that
are not on the recorded list; it cannot catch a destination that is on the list but that no query
actually reads. Keeping the list short and each entry genuinely ingested is the only defence.

**The dark window has soft edges.** Because delivery lags configuration by around an hour in both
directions, neither the start nor the end of the gap is exact, and some records from before the
change may never have been delivered at all. Any timeline built from access logs should carry that
caveat explicitly.

**A prefix-only change is rated P2 and may deserve more.** Changing `TargetPrefix` alone leaves
everything looking correct at bucket granularity and delivers records where nothing ingests them. It
is rated lower only because it is far more often a legitimate reorganisation — which is exactly what
makes it the quietest option available to someone who knows that.
*A prefix-only change is rated P2 and may deserve more.** Changing `TargetPrefix` while keeping the
same `TargetBucket` leaves everything looking correct at bucket granularity and delivers records
where nothing ingests them. It is rated lower only because it is far more often a legitimate
reorganisation, which makes it the quietest option available to someone who knows that.
