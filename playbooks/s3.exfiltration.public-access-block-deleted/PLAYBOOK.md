# IR Playbook: S3 Block Public Access Removed — the guardrail deleted via `DeleteBucketPublicAccessBlock`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Collection precondition (the control that refuses a public bucket policy or ACL is removed, leaving nothing to stop the next write) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High for a bucket, Critical for the account-level equivalent. Removing the block exposes nothing by itself — it is a gate on what a policy may say — but it is the only step that has to happen first, and account-level removal weakens every bucket in the account at once. The source rule rates this P3 and, as written, cannot fire at all. |
| MITRE Tactics | Collection |
| MITRE Techniques | T1530 |
| Services in Scope | S3, IAM, CloudTrail, AWS Config, GuardDuty |

**What the technique does:** the actor calls `DeleteBucketPublicAccessBlock` on a bucket, or
`DeleteAccountPublicAccessBlock` on the account. Nothing becomes public. What changes is that S3
will now **accept** a public bucket policy or a public ACL, where before it refused them —
`BlockPublicPolicy` rejects a `PutBucketPolicy` that allows public access, and `BlockPublicAcls`
rejects a public ACL. With the block gone, the next `PutBucketPolicy` succeeds, and the objects are
readable by anyone.

**Why the usual reflexes miss it.** The first reflex is to alert on the bucket becoming public,
which is the second act — by then the data is exposed and the window is over. The second is to
match the API operation name, which is what the source rule does and why it has never fired: AWS
emits `DeleteBucketPublicAccessBlock` for the bucket, not `DeletePublicAccessBlock`. The third is
to re-enable the block during containment and consider the bucket closed, which it may not be —
three of the four flags only affect **future** writes.

**Detection thesis:** the deletion is the precondition and the ordered pair is the incident. Alert
on the removal, correlate it with the policy or ACL write that follows, and treat the account-level
event as a separate and larger case.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **CloudTrail management events for `s3.amazonaws.com`.** S3 logs all control-plane operations as
  management events and bucket-level calls are on by default. The event names that matter are
  `DeleteBucketPublicAccessBlock`, `PutBucketPublicAccessBlock` and their `...Account...`
  equivalents — and they are **not** the API operation names.
- **S3 data events where the data warrants it.** Object reads are data events, off by default and
  billable. Without them, "was the exposed data read" cannot be answered after the fact, and it
  cannot be enabled retroactively.
- **AWS Config recording `AWS::S3::Bucket`.** It carries the policy and the public-access-block
  state and is the only source of what the configuration looked like before the trail window.
- **The intended Block Public Access state per bucket**, in infrastructure code, so live state is a
  diff rather than a judgement.

**Alerting (must be pre-configured)**
- **`DeleteBucketPublicAccessBlock` succeeding for a principal outside the provisioning allowlist → P0**
- **`DeleteAccountPublicAccessBlock` succeeding, by anyone → P0**
- **A `PutBucketPolicy` or `PutBucketAcl` by the same principal within an hour of a block removal → P0**
- **`DeleteBucketPublicAccessBlock` on more than one bucket by one principal in an hour → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under
  investigation, and `jq`.
- An unauthenticated client — `curl` with no credentials — to test public reachability from outside.
  Testing with credentials proves nothing about anonymous access.
- The bucket's intended policy and ACL from infrastructure code, to restore from rather than
  reconstruct.

**Known IOC Baselines**
- **Which principals legitimately manage bucket access configuration.** In an IaC estate this is one
  role, and it is the tuning surface for the whole detection.
- The buckets that are *intended* to serve public content, as an explicit list with an owner. Every
  other bucket having a block removed is the finding.
- The account-level Block Public Access state, recorded — it is a single setting protecting
  everything, and most estates never look at it.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `DeleteAccountPublicAccessBlock` succeeding — weakens every bucket in the account | CloudTrail (management) | T1530 |
| P0 | `DeleteBucketPublicAccessBlock` then `PutBucketPolicy`/`PutBucketAcl` by the same principal within 1h | CloudTrail (correlation) | T1098 |
| P0 | `DeleteBucketPublicAccessBlock` by a principal outside the provisioning allowlist | CloudTrail (management) | T1530 |
| P1 | `DeleteBucketPublicAccessBlock` on more than one bucket by one principal within an hour | CloudTrail (management) | T1530 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `PutBucketPublicAccessBlock` submitting a subset of flags that weakens the existing state | CloudTrail (management) | T1530 |
| P2 | A bucket whose live block state differs from infrastructure code, in the scheduled sweep | `get-public-access-block` | T1530 |
| P3 | `GetBucketPublicAccessBlock` or `GetBucketPolicyStatus` enumeration across many buckets | CloudTrail (management) | T1580 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Matches `DeletePublicAccessBlock` — the SDK operation name | AWS emits `DeleteBucketPublicAccessBlock` for a bucket and documents that the CloudTrail name differs from the API name. **The rule cannot fire**, in any account, ever. It reports clean permanently and a coverage review reads that as satisfied | Match the CloudTrail event name. Verified against the S3 CloudTrail events list, which enumerates both forms |
| No account-scope coverage | `DeleteAccountPublicAccessBlock` is a different event, and AWS applies "the most restrictive combination of the bucket-level and account-level settings" — so removing the account block weakens every bucket whose own configuration is weaker or absent | A dedicated rule at critical, rated above the bucket case because one event affects everything |
| Treats the removal as the exposure | The block gates what a policy or ACL may say; it is not an access control. Alerting on removal alone gives a responder no blast radius, because nothing is public yet | An ordered correlation pairing the removal with the policy or ACL write that follows. The pair is the incident |
| No principal filter | In an IaC estate every bucket rebuild removes and rewrites the configuration, so an unfiltered rule fires on routine applies | `known_provisioners` on the bucket rule, left empty by default so the first week's output builds the list |
| Rated P3 | This is the only step that must happen before a bucket can be made public. Rating it below the exposure inverts the order in which a responder can still act | High for the bucket case, critical for account scope and for the ordered pair |
| MITRE: none | The pack maps this rule to nothing at all | `T1530 — Data from Cloud Storage` for the objective; `T1098` on the correlation where a grant follows |

**Recommended detection — the removal, the account-scope case, and the pair.**

```yaml
# S3 Block Public Access removed from a bucket (T1530)
#
# THE SOURCE RULE NAMES THE SDK OPERATION, NOT THE CLOUDTRAIL EVENT, AND SO CANNOT FIRE. It matches
# `DeletePublicAccessBlock`; AWS emits `DeleteBucketPublicAccessBlock`. The value is never present,
# so the rule reports clean in every account forever.
#
# Removing the block does not itself expose anything — it gates what a policy or ACL is ALLOWED to
# say, so the exposure needs a second act. The deletion is the precondition and the ordered pair is
# the incident. Account scope is a separate event with a larger blast radius.
# Full rationale: detections/detection_note_t1530.md.
title: S3 Block Public Access deleted from a bucket
id: 5a3f19c8-2704-4b6e-9d81-e60c473a2b15
name: s3_bucket_pab_deleted
status: experimental
description: >-
  DeleteBucketPublicAccessBlock removed the bucket's Block Public Access configuration. The bucket
  is not public yet — the block is a gate on what a policy or ACL may do, not an access control in
  itself — but every guardrail that would have refused a public policy or a public ACL is now gone.
  Note the event name: this is the CloudTrail form, which differs from the API operation
  DeletePublicAccessBlock that the source rule matches.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html
  - https://attack.mitre.org/techniques/T1530/
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName: 'DeleteBucketPublicAccessBlock'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the roles that own bucket lifecycle. An empty list reports every
  # deletion once, which is the correct starting position for a guardrail being removed.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    A bucket being decommissioned, or one deliberately serving public content where the block was
    never appropriate. Both are nameable exceptions; neither is frequent enough to tune away.
level: high
---
title: S3 Block Public Access deleted at the ACCOUNT level
id: c8140b62-9e35-4a07-b2f6-70d3859ec4a1
name: s3_account_pab_deleted
status: experimental
description: >-
  DeleteAccountPublicAccessBlock removed the account-wide Block Public Access configuration. AWS
  evaluates bucket and account settings together and applies "the most restrictive combination", so
  the account block is what holds the line for every bucket whose own configuration is weaker or
  absent. Removing it weakens all of them simultaneously and emits an event no bucket-scoped rule
  matches. There is no benign routine reason to remove it; a bucket that must serve public content
  is handled at the bucket, not by lowering the account floor.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html
  - https://attack.mitre.org/techniques/T1530/
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName: 'DeleteAccountPublicAccessBlock'
  success:
    errorCode: null
  condition: selection and success
falsepositives:
  - >-
    An account genuinely repurposed for public static hosting. Rare, deliberate, and it should be a
    recorded decision rather than a tuning exception.
level: critical
---
title: S3 bucket policy or ACL written
id: 20e7c9b4-518d-46fa-83c0-9147e6205daf
name: s3_bucket_exposure_write
status: experimental
description: >-
  Base rule — correlation component only, not for direct alerting. Any write to a bucket's policy or
  ACL. It fires on ordinary infrastructure applies and must never be routed anywhere on its own; it
  exists so the correlation below can pair an exposure with the guardrail removal that preceded it.
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
---
title: Block Public Access removed and then the bucket opened
id: 7b06e2d1-43c9-4085-a7e2-1d9508fb3c47
status: experimental
description: >-
  The guardrail was removed and a policy or ACL was written afterwards by the same principal. This
  is the sequence that turns a configuration change into an exposure: Block Public Access refuses a
  public policy while it is in force, so an actor who wants one has to remove it first. Ordering is
  the whole signal — the reverse order is ordinary maintenance. Timespan is 1h because this is a
  single deliberate session rather than a campaign; group-by is the principal because the bucket
  name is not carried identically across both events.
references:
  - https://attack.mitre.org/techniques/T1530/
  - https://attack.mitre.org/techniques/T1098/
tags:
  - attack.collection
  - attack.persistence
  - attack.t1530
  - attack.t1098
correlation:
  type: temporal_ordered
  rules:
    - s3_bucket_pab_deleted
    - s3_bucket_exposure_write
  group-by:
    - userIdentity.arn
  timespan: 1h
falsepositives:
  - >-
    An infrastructure apply that recreates a bucket's configuration from scratch, which legitimately
    removes and rewrites in one run. Allowlist the provisioning role on the base rule rather than
    widening the timespan.
level: critical
```

What this set structurally cannot do: it cannot tell you whether anything was read, because object
operations are data events that are off by default and cannot be enabled retroactively. And for an
ACL set by another account it cannot tell you what was granted — AWS redacts the grantee and the
grant from the bucket owner's copy of the event.

---

### Key Investigation Queries

> S3 bucket-level calls are **management** events and on by default; object-level calls are **data**
> events and are not. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform
> for busy windows.

#### Query 1 — Reconstruct: what was removed, by whom, and what followed

```bash
REGION="us-east-1"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

for EV in DeleteBucketPublicAccessBlock DeleteAccountPublicAccessBlock \
          PutBucketPublicAccessBlock PutAccountPublicAccessBlock \
          PutBucketPolicy PutBucketAcl DeleteBucketPolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$SINCE" --region "$REGION" --output json 2>/dev/null | \
    jq -r '.Events[].CloudTrailEvent | fromjson |
      select(.eventSource == "s3.amazonaws.com") |
      {time: .eventTime, event: .eventName, caller: .userIdentity.arn,
       access_key: .userIdentity.accessKeyId,
       bucket: (.requestParameters.bucketName // "<account-scope>"),
       pab: (.requestParameters.PublicAccessBlockConfiguration // "-"),
       error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}'
done | jq -s 'sort_by(.time)'
```

Read it as a sequence. A removal followed by a `PutBucketPolicy` on the same bucket is the exposure;
a removal with nothing after it is a bucket mid-change or a decommission. A `bucket` of
`<account-scope>` is the account-level event — that one affects every bucket and should be read
first regardless of where it appears in the ordering.

#### Query 2 — Sweep: the live block state of every bucket, and the account

```bash
REGION="us-east-1"

echo "== account-level Block Public Access =="
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
aws s3control get-public-access-block --account-id "$ACCOUNT" --output json 2>/dev/null | \
  jq -r '.PublicAccessBlockConfiguration |
    "[\(if (.BlockPublicAcls and .IgnorePublicAcls and .BlockPublicPolicy and .RestrictPublicBuckets) then "OK]  " else "FAIL]" end) account: acls=\(.BlockPublicAcls) ignore=\(.IgnorePublicAcls) policy=\(.BlockPublicPolicy) restrict=\(.RestrictPublicBuckets)"' \
  || echo "[FAIL] account: NO public access block configured at all"

echo
echo "== per bucket =="
for B in $(aws s3api list-buckets --output json | jq -r '.Buckets[].Name'); do
  aws s3api get-public-access-block --bucket "$B" --output json 2>/dev/null | \
    jq -r --arg b "$B" '.PublicAccessBlockConfiguration |
      "[\(if (.BlockPublicAcls and .IgnorePublicAcls and .BlockPublicPolicy and .RestrictPublicBuckets) then "OK]  " else "!]   " end) \($b): acls=\(.BlockPublicAcls) ignore=\(.IgnorePublicAcls) policy=\(.BlockPublicPolicy) restrict=\(.RestrictPublicBuckets)"' \
    || echo "[FAIL] $B: NO public access block"
done
```

Read the account line first: it is the floor for everything, and a weak account setting makes every
`[OK]` below it less meaningful than it looks. `[FAIL]` on a bucket means no configuration at all,
which is the same practical state as one that was deleted — and only Query 1 distinguishes "never
had one" from "just lost one".

#### Query 3 — Inspect: is the bucket actually public right now

```bash
REGION="us-east-1"
BUCKET="<bucket-from-Query-1>"

echo "== AWS's own verdict on whether the policy is public =="
aws s3api get-bucket-policy-status --bucket "$BUCKET" --output json 2>/dev/null | \
  jq -r '"IsPublic=\(.PolicyStatus.IsPublic)"' || echo "[i] no bucket policy attached"

echo
echo "== the policy itself =="
aws s3api get-bucket-policy --bucket "$BUCKET" --output json 2>/dev/null | \
  jq -r '.Policy | fromjson | .Statement[]
    | select(.Effect == "Allow")
    | "principal=\(.Principal | tostring)  action=\(.Action | tostring)"' \
  || echo "[i] none"

echo
echo "== the ACL, which a cross-account grant does NOT show in the owner's trail =="
aws s3api get-bucket-acl --bucket "$BUCKET" --output json 2>/dev/null | \
  jq -r '.Grants[] | "grantee=\(.Grantee.URI // .Grantee.ID // .Grantee.DisplayName // "-")  perm=\(.Permission)"'

echo
echo "== anonymous reachability, from outside =="
CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "https://${BUCKET}.s3.${REGION}.amazonaws.com/" 2>/dev/null)
case "$CODE" in
  200) echo "[FAIL] anonymous LIST succeeded — the bucket is publicly listable" ;;
  403) echo "[OK] anonymous request denied" ;;
  404) echo "[i] 404 — bucket exists but no index; not conclusive about object access" ;;
  *)   echo "[!] HTTP $CODE — verify by another means" ;;
esac
```

`get-bucket-policy-status` is AWS's own evaluation of whether the policy is public and it is more
reliable than reading the statements by eye. The ACL query matters because a grantee URI of
`http://acs.amazonaws.com/groups/global/AllUsers` is public read — and if that grant was made by
another account, the owner's CloudTrail copy does not contain it.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique)})'
```

Keyed on the access key rather than the ARN, since one credential spans many sessions. Look for
`GetBucketPublicAccessBlock` or `GetBucketPolicyStatus` across many buckets before the removal —
that is the enumeration that chose the target, and it is a read that nothing else alerts on.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore the block, then check the policy and the ACL — because restoring the block does not undo
either. That second step is not optional and it is the one most often skipped.

> Run every command under the **break-glass responder credentials** from §1, not under any principal
> being investigated.

#### Step 1 — Restore Block Public Access, at both scopes

```bash
REGION="us-east-1"
BUCKET="<bucket-from-Query-1>"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
  && echo "[OK] bucket block restored on $BUCKET"

aws s3control get-public-access-block --account-id "$ACCOUNT" --output json >/dev/null 2>&1 \
  || aws s3control put-public-access-block --account-id "$ACCOUNT" \
       --public-access-block-configuration \
       BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
     && echo "[i] account-level block present or restored"
```

All four flags are set explicitly because each is `Required: No` and AWS does not document
merge-versus-replace for a partial document — submitting a subset leaves the rest ambiguous.

#### Step 2 — Check the policy and the ACL, because Step 1 did not fix them

```bash
BUCKET="<bucket>"

echo "[!] Enabling the block is prospective for three of four flags. AWS:"
echo "    BlockPublicAcls   — 'doesn't affect existing policies or ACLs'"
echo "    BlockPublicPolicy — 'doesn't affect existing bucket policies'"
echo "    IgnorePublicAcls  — 'doesn't affect the persistence of any existing ACLs'"
echo

aws s3api get-bucket-policy-status --bucket "$BUCKET" --output json 2>/dev/null | \
  jq -r 'if .PolicyStatus.IsPublic then "[FAIL] the bucket policy is STILL public — remove or rewrite it"
         else "[OK] bucket policy is not public" end' \
  || echo "[i] no bucket policy attached"

aws s3api get-bucket-acl --bucket "$BUCKET" --output json 2>/dev/null | \
  jq -r 'if ([.Grants[].Grantee.URI // ""] | any(test("AllUsers|AuthenticatedUsers")))
         then "[FAIL] the ACL still grants a public group — rewrite it"
         else "[OK] no public ACL grant" end'
```

`RestrictPublicBuckets` does neutralise a public *policy* while it is in force, but a `[FAIL]` here
means the configuration is still public in its own right and would take effect the moment the block
is removed again. Fix the underlying object, not just the gate.

#### Step 3 — Remove the public grant from the bucket's own configuration

```bash
REGION="us-east-1"
BUCKET="<bucket>"
GOOD_POLICY="<path-to-intended-policy.json>"
CASE_DIR="./ir-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$CASE_DIR"

aws s3api get-bucket-policy --bucket "$BUCKET" --output json > "$CASE_DIR/policy-before.json" 2>/dev/null
aws s3api get-bucket-acl    --bucket "$BUCKET" --output json > "$CASE_DIR/acl-before.json" 2>/dev/null
echo "[i] prior state captured in $CASE_DIR"

if [ -f "$GOOD_POLICY" ]; then
  aws s3api put-bucket-policy --bucket "$BUCKET" --policy "file://$GOOD_POLICY" \
    && echo "[OK] policy restored from infrastructure code"
else
  echo "[i] no known-good policy file. If the bucket should have NO policy, delete it rather than"
  echo "    guessing:  aws s3api delete-bucket-policy --bucket $BUCKET"
fi
aws s3api put-bucket-acl --bucket "$BUCKET" --acl private \
  && echo "[OK] ACL set to private"
```

#### Step 4 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')      # user ARN: name = last segment
  aws iam put-user-policy --user-name "$U" --policy-name IR-Deny-All \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')       # role ARN: name = 2nd segment
  cat > /tmp/revoke.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"REVOKE_BEFORE"}}}]}
JSON
  sed -i.bak "s/REVOKE_BEFORE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" /tmp/revoke.json
  aws iam put-role-policy --role-name "$R" --policy-name AWSRevokeOlderSessions \
    --policy-document file:///tmp/revoke.json
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

---

## 4. Eradication

### Remove Attacker Access

#### Treat the exposure window as full disclosure

Object reads are data events and are off by default, so unless a data-event trail already existed
there is no record of what was retrieved. Do not spend the response looking for evidence that
cannot exist — scope from *what the bucket contained* and rotate anything in it that is a
credential, a token or a key.

#### Close every other bucket the sweep found

Query 2's `[!]` and `[FAIL]` lines are the backlog. Most will be buckets nobody ever configured
rather than buckets that were tampered with, and both are the same exposure.

#### Set the account-level block as the floor

An account-level block with all four flags true means a bucket-level removal cannot make anything
public on its own, because AWS applies the most restrictive combination. It converts this technique
from a one-step exposure into a two-step one that needs account-level permission.

#### Right-size who can change bucket access configuration

`s3:PutBucketPublicAccessBlock`, `s3:DeleteBucketPublicAccessBlock`, `s3:PutBucketPolicy` and
`s3:PutBucketAcl` belong to a platform role. Query 4's principal is the starting point.

---

## 5. Recovery

### Restore Clean State

#### Verify no bucket is public and the account floor is set

```bash
REGION="us-east-1"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
BAD=0

aws s3control get-public-access-block --account-id "$ACCOUNT" --output json 2>/dev/null | \
  jq -e '.PublicAccessBlockConfiguration | .BlockPublicAcls and .IgnorePublicAcls
         and .BlockPublicPolicy and .RestrictPublicBuckets' >/dev/null \
  && echo "[OK] account-level block is fully enabled" \
  || { echo "[FAIL] account-level block is absent or partial"; BAD=$((BAD+1)); }

for B in $(aws s3api list-buckets --output json | jq -r '.Buckets[].Name'); do
  PUB=$(aws s3api get-bucket-policy-status --bucket "$B" --output text \
        --query 'PolicyStatus.IsPublic' 2>/dev/null)
  [ "$PUB" = "True" ] && { echo "[FAIL] $B has a public policy"; BAD=$((BAD+1)); }
done
[ "$BAD" -eq 0 ] && echo "[OK] no public bucket policy and the account floor is set"
```

#### Verify from outside, unauthenticated

```bash
BUCKET="<bucket>"
REGION="us-east-1"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "https://${BUCKET}.s3.${REGION}.amazonaws.com/" 2>/dev/null)
[ "$CODE" = "403" ] && echo "[OK] anonymous request denied" \
                    || echo "[FAIL] anonymous request returned $CODE"
```

Credentials must not be used here. The question is what an anonymous caller can reach, and an
authenticated test answers a different one.

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  eventSource=s3.amazonaws.com  eventName=DeleteBucketPublicAccessBlock  no errorCode"
echo "  (this is the CloudTrail event name; the source rule matches DeletePublicAccessBlock,"
echo "   which is the API operation name and never appears in a bucket-level record)"
echo "and MUST fire at critical on:"
echo "  eventName=DeleteAccountPublicAccessBlock"
echo "The rule MUST NOT fire on:"
echo "  DeleteBucketPublicAccessBlock by an ARN in known_provisioners"
echo "  PutBucketPublicAccessBlock with all four flags true (that is the guardrail being restored)"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A bucket's Block Public Access was removed and nothing alerted | The rule matched the API operation name rather than the CloudTrail event name, so it had never fired |
| The account-level block did not hold the line | It was absent or partial, so the bucket-level removal was sufficient on its own |
| The removal was reachable by a non-platform principal | `s3:DeleteBucketPublicAccessBlock` granted broadly, and treated as a configuration action rather than a security control |
| Re-enabling the block did not close the bucket | Three of the four flags affect only future writes; the existing public policy stayed in force |
| The exposure could not be scoped | Object-level data events were not enabled, so what was read is unknowable |

### Recommended Guardrails

**Deny removal of the block outside the platform role**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["s3:PutBucketPublicAccessBlock", "s3:PutAccountPublicAccessBlock",
             "s3:PutBucketPolicy", "s3:PutBucketAcl"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Set account-level Block Public Access with all four flags and treat it as a floor. AWS applies the
  most restrictive combination, so this makes a bucket-level removal insufficient on its own.
- Record `AWS::S3::Bucket` in AWS Config. It is the only source of the previous policy and block
  state once the trail window passes.
- Enable S3 data events on buckets holding data whose disclosure would matter. It is billable and it
  is the only thing that can ever answer "was it read".
- Keep the list of intentionally-public buckets short, owned and reviewed. Every bucket not on it
  having its block removed is unambiguous.

**Detection improvements**
- Check the CloudTrail event name against AWS's own list rather than assuming it matches the API
  operation. S3 diverges for several operations and the divergence is per-operation — a sibling rule
  in this same pack gets `PutBucketPublicAccessBlock` right while this one gets the delete wrong.
- Cover account scope separately. It is a different event name and a larger blast radius.
- Correlate the removal with the write that follows. The removal alone has no blast radius and the
  write alone loses the window in which the response could still have been preventive.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1530 — Data from Cloud Storage |
| MITRE tactic | Collection (TA0009) |
| Primary API | `s3:DeletePublicAccessBlock` — logged by CloudTrail as **`DeleteBucketPublicAccessBlock`** |
| Event source | s3.amazonaws.com, management plane, on by default. Object reads are **data** events and are off by default |
| Key discriminator | The event itself, plus the principal. Block Public Access has no benign reason to be removed from a bucket that is not intended to be public |
| Ground-truth signal | `get-public-access-block` at both bucket and account scope, and `get-bucket-policy-status` for AWS's own verdict on whether the policy is public |
| "Was it used" pivot | Not available without pre-existing data events. An unauthenticated `curl` establishes current reachability, not historical access |
| Blast radius | Every object in the bucket, if a public policy or ACL followed. For the account-scope event, every bucket whose own configuration is weaker or absent |
| Error strings | `NoSuchPublicAccessBlockConfiguration` when none is set; `AccessDenied` / `AccessDeniedException` on refusal — match both forms |

**MITRE mapping note:** the source pack maps this rule to **nothing at all**. `T1530 — Data from
Cloud Storage` names the objective, since the point of removing the block is to make stored data
readable. `T1098 — Account Manipulation` is carried on the correlation, where the removal is
followed by a grant to a principal that did not have access. Both verified live 2026-08-30.

### Residual Risk

If a public policy or ACL was in force at any point, treat every object in the bucket as disclosed:
object reads are data events that are off by default and cannot be enabled retroactively, so the
absence of read records is not evidence and never will be. Re-enabling Block Public Access does not
revoke a public policy — three of the four flags are prospective, so the bucket may still be public
in its own configuration after the block is restored, and only reading the policy and ACL shows it.
For an ACL granted by another account, the owner's trail records that the call happened and not what
it granted, so the live ACL is the only account of it. And anything already retrieved — a credential,
a token, a key in an object — stays valid until it is rotated, whatever the bucket's configuration
now says.
