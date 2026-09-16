# IR Playbook: S3 Bucket Policy Made Public — a wildcard-principal grant written via `PutBucketPolicy`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Collection — a bucket policy statement grants access to a wildcard principal, making the bucket's contents readable by anyone AWS evaluates as "public" |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. Critical when a Block Public Access gate was lowered immediately before, because that pair describes a completed exposure rather than a single ambiguous act. |
| MITRE Tactics | Collection |
| MITRE Techniques | T1530 |
| Services in Scope | S3, IAM, CloudTrail, GuardDuty |

**What the technique does:** the actor writes a bucket policy containing an `Allow` to `"*"`. If
`BlockPublicPolicy` is set, S3 refuses the call — AWS: it *"causes Amazon S3 to reject calls to
`PutBucketPolicy` if the specified bucket policy allows public access."* So a successful public
write is not merely an outcome, it is **evidence that the guardrail was false at that instant**, and
the guardrail state at write time is recoverable from the write alone.

**Why the usual reflexes miss it.** The first is to trust a "made public" boolean, which is what the
source rule does and which no AWS field provides. The second is to decide public-versus-not by
reading the statement: AWS *"begins by assuming that the policy is public"* and only calls it
non-public if access is granted to **fixed** values of an enumerated set of keys, so a statement
that looks scoped may not be and a statement that looks open may be fine. The third is to restore
the guardrail and close the ticket, which suppresses the grant without removing it. The fourth is to
be surprised when containment breaks a partner integration — one public statement makes the whole
policy public, and `RestrictPublicBuckets` then disables the cross-account access the other
statements were granting.

**Detection thesis:** find the write, let AWS adjudicate whether it was public, and treat the write
succeeding as evidence about the gate.

**Adjacent playbooks.** The gate being lowered is
`../s3.exfiltration.public-access-block-removed/`; deleted outright,
`../s3.exfiltration.public-access-block-deleted/`. Exposure by ACL rather than policy is
`../s3.exfiltration.bucket-acl-configured/`; the policy removed rather than written is
`../s3.impact.bucket-policy-deleted/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. `PutBucketPolicy` is a bucket-level call, so it is a
management event and on by default — and the event carries the **policy document itself**, which is
what makes any of this analysable without the platform enrichment the source rule depended on.

CloudTrail **data events** on buckets holding sensitive data: off by default, billable, not
enablable retroactively. They are the only way to answer "was anything read during the exposure",
and that question is the one that determines whether this becomes a disclosure.

`s3:GetBucketPolicyStatus` available to the responding principal. AWS's own evaluator is the arbiter
for every alert this playbook produces, and a responder who cannot call it is reduced to reading
policy documents by eye — which is precisely how conditioned-but-public statements get closed as
false positives.

**Alerting (must be pre-configured)**

- **Block Public Access gate lowered, then a wildcard-principal policy written by the same principal within 1h → P0**
- **`PutBucketPolicy` with a wildcard-principal Allow succeeds and `GetBucketPolicyStatus` returns `True` → P0**
- **A scoping condition carrying a wildcard value — `StringLike` on `aws:SourceVpc` or a sibling key → P1**

**Response Tooling**

An IAM principal that can call `s3api put-bucket-policy`, `delete-bucket-policy` and
`put-public-access-block` outside the change pipeline.

A place to write the policy backup before modifying it. A bucket policy is frequently the only
record of a cross-account arrangement, and the containment step removes statements from it.

`curl` from outside the account, for the unauthenticated verification in §5. The internal API view
and the internet view can disagree and only one of them answers a disclosure question.

**Known IOC Baselines**

The list of buckets that are public **on purpose**, shared with the other `s3.*` playbooks. Without
it, a static-site bucket produces this alert every time it is deployed.

The roles that own bucket lifecycle, populating `known_provisioners`. Every infrastructure apply
that manages a bucket policy rewrites it in full.

The cross-account consumers of each bucket policy, so that the collateral damage in §3 Step 2 is
predictable rather than discovered. `RestrictPublicBuckets` disables cross-account access derived
from a policy that any statement has made public, so a partner can lose access without their
statement being touched.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | Block Public Access gate lowered, then a wildcard-principal policy written by the same principal within 1h | Correlation rule | T1530 |
| P0 | `PutBucketPolicy` with a wildcard-principal `Allow` succeeds and `GetBucketPolicyStatus` returns `True` | CloudTrail + API | T1530 |
| P1 | A scoping condition carrying a wildcard value — `StringLike` on `aws:SourceVpc` or a sibling key, which AWS evaluates as public | CloudTrail | T1530 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | A wildcard-principal `Allow` succeeds with no gate-lowering event in the window — the gate was already down before it | CloudTrail | T1530 |
| P2 | Wildcard principal fixed by a scoping condition — AWS evaluates it non-public, but the statement is one edit from public | CloudTrail | T1530 |
| P2 | A public statement added to a policy that also delegates to a named account — the delegated access silently stops working | CloudTrail | T1530 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Its only predicate is `requestParameters.bucketPolicy.bucket_made_public` | That path appears in no AWS documentation, and it is snake_case where every documented S3 `requestParameters` field is camelCase. It is platform enrichment. The rule works where it was authored and silently reports clean anywhere the enrichment is absent — no error, no gap in the dashboard | Work from the policy document, which CloudTrail does carry in the event, and adjudicate with `GetBucketPolicyStatus` |
| A boolean cannot carry AWS's evaluation | AWS *"begins by assuming that the policy is public"* and calls it non-public only if access is granted to **fixed** values of an enumerated key list. A wildcard principal with a fixed `aws:SourceVpce` is not public; the same with `"vpc-*"` is | Rules that deliberately over-match, with the direction of error stated, and a triage step that calls AWS's evaluator rather than reading statements |
| No coverage of the conditioned-but-public case | `"StringLike": {"aws:SourceVpc": "vpc-*"}` is AWS's own worked public example. It reads as scoped, so a human reviewer sees a condition and stops — this is the shape most likely to be waved through | A dedicated rule on a wildcard operator over one of the scoping keys, shipped separately so it is triaged as its own case |
| Discards the strongest available inference | A public policy write that **succeeded** proves `BlockPublicPolicy` was false at that moment, because S3 rejects the call when it is set. That is free evidence about the guardrail | Stated in the rule, the query and §2 below, and used to distinguish "the gate was lowered just now" from "the gate has been down for months" |
| No principal filter | Every infrastructure apply that manages a bucket policy rewrites it in full, so an unfiltered rule fires on routine deploys | `known_provisioners`, shipped with placeholders that must be populated |
| MITRE: none | The pack maps this rule to nothing at all | `T1530 — Data from Cloud Storage` |

**Recommended detection — the write, the conditioned variant, and the pair with the gate.**

```yaml
# S3 bucket policy made public (T1530)
#
# AWS'S EVALUATION RUNS BACKWARDS FROM THE OBVIOUS ONE. "Amazon S3 begins by assuming that the
# policy is public. It then evaluates the policy to determine whether it qualifies as NON-public" —
# which requires access granted only to FIXED values of an enumerated key list. So these rules
# deliberately OVER-match, and every hit is resolved with GetBucketPolicyStatus rather than by
# reading the policy.
#
# A public write that SUCCEEDS proves BlockPublicPolicy was false at that instant, because S3
# rejects the call when it is set. Full rationale: detections/detection_note_t1530.md.
title: S3 bucket policy written granting to a wildcard principal
id: 5b8c47e1-93da-4b26-a7f0-6c1e28d40b9f
name: s3_bucket_policy_public_principal
status: experimental
description: >-
  A successful PutBucketPolicy whose document contains an Allow to a wildcard principal. Because
  BlockPublicPolicy makes S3 reject exactly this call when it is set, a success here is also
  evidence that the guardrail was false at that moment. Over-matches by design — AWS treats a
  wildcard principal fixed by one of an enumerated set of condition keys as non-public — so every
  hit is resolved with GetBucketPolicyStatus rather than by reading the statement.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html
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
    eventName: 'PutBucketPolicy'
  success:
    errorCode: null
  # The policy document is serialised into the event. Both spellings of a wildcard principal are
  # matched: the bare string form and the {"AWS": "*"} form, with and without whitespace.
  wildcard_principal:
    requestParameters.bucketPolicy|contains:
      - '"Principal":"*"'
      - '"Principal": "*"'
      - '"AWS":"*"'
      - '"AWS": "*"'
  allow:
    requestParameters.bucketPolicy|contains:
      - '"Effect":"Allow"'
      - '"Effect": "Allow"'
  # POPULATE BEFORE DEPLOYING with the roles that own bucket lifecycle.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and wildcard_principal and allow and not known_provisioners
falsepositives:
  - >-
    A statement whose wildcard principal is fixed by aws:SourceVpce, aws:SourceArn or another key on
    AWS's enumerated list, which AWS evaluates as non-public. GetBucketPolicyStatus settles it;
    narrowing the rule to exclude conditioned statements would also exclude the conditioned ones
    that are public.
  - >-
    A bucket deliberately serving public content. It should be on the recorded public-bucket list.
level: high
---
title: S3 bucket policy condition re-publicised by a wildcard in its value
id: a3f1690c-24e8-4d73-b58a-71c9e0d6f254
name: s3_bucket_policy_wildcard_condition
status: experimental
description: >-
  A PutBucketPolicy carrying a condition on one of the keys that can make a policy non-public, but
  whose value contains a wildcard. AWS's own worked example is exactly this: `"StringLike":
  {"aws:SourceVpc": "vpc-*"}` is public, while `"StringEquals": {"aws:SourceVpc": "vpc-91237329"}`
  is not. This is the shape that survives review, because the statement looks scoped — the reviewer
  sees a condition and stops reading. Shipped separately because it is the one a human is most
  likely to wave through.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
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
    eventName: 'PutBucketPolicy'
  success:
    errorCode: null
  conditioned_on_a_scoping_key:
    requestParameters.bucketPolicy|contains:
      - 'aws:SourceVpc'
      - 'aws:SourceVpce'
      - 'aws:SourceArn'
      - 'aws:SourceAccount'
      - 'aws:SourceOwner'
      - 'aws:SourceIp'
  # StringLike is the operator that admits a wildcard; StringEquals does not. A StringLike on a
  # scoping key is the documented public case.
  wildcard_operator:
    requestParameters.bucketPolicy|contains:
      - '"StringLike"'
      - '"ArnLike"'
  condition: selection and success and conditioned_on_a_scoping_key and wildcard_operator
falsepositives:
  - >-
    A StringLike whose pattern happens to contain no wildcard character. Rare, because there is no
    reason to use StringLike without one, and worth reviewing when it appears.
level: medium
---
title: Block Public Access gate lowered and a public policy then written
id: 2c74d9b6-8e15-4a30-96f7-b0d3e847152a
status: experimental
description: >-
  A Block Public Access flag was set false and a wildcard-principal policy was written afterwards by
  the same principal. This is the sequence BlockPublicPolicy exists to make impossible: with it set,
  S3 rejects the write, so the gate has to come down first. Critical because the two halves together
  describe a completed exposure, where either alone is ambiguous.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
  - https://attack.mitre.org/techniques/T1530/
tags:
  - attack.collection
  - attack.t1530
correlation:
  type: temporal_ordered
  rules:
    - s3_pab_gate_lowered
    - s3_bucket_policy_public_principal
  group-by:
    - userIdentity.arn
  timespan: 1h
level: critical
---
title: S3 Block Public Access policy gate lowered
id: 8d2b53f7-6c09-41ae-b4d8-e5107a9c3b62
name: s3_pab_gate_lowered
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. BlockPublicPolicy set to false,
  or the Block Public Access configuration deleted outright, at either scope. The rated detections
  for this act are in ../../s3.exfiltration.public-access-block-removed/ and
  ../../s3.exfiltration.public-access-block-deleted/.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  # Three keys ANDed, and they do co-occur on a single event: a PutBucketPublicAccessBlock record
  # carries eventSource, eventName and the submitted flags together.
  put_gate_down:
    eventSource: 's3.amazonaws.com'
    eventName:
      - 'PutBucketPublicAccessBlock'
      - 'PutAccountPublicAccessBlock'
    requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy: false
  deleted:
    eventSource: 's3.amazonaws.com'
    eventName:
      - 'DeleteBucketPublicAccessBlock'
      - 'DeleteAccountPublicAccessBlock'
  success:
    errorCode: null
  condition: (put_gate_down or deleted) and success
level: informational
```

What this set structurally cannot do: it cannot reproduce AWS's public/non-public evaluation, and it
does not try — `GetBucketPolicyStatus` is the arbiter and the rules produce candidates for it. And
it cannot tell you whether anything was read, because object operations are data events that are off
by default and cannot be enabled retroactively.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

Run Query 1 first; it produces the bucket and principal the rest take as input.

#### Query 1 — Reconstruct: the write, whether it succeeded, and the gate around it

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in PutBucketPolicy DeleteBucketPolicy PutBucketPublicAccessBlock DeleteBucketPublicAccessBlock; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | (.requestParameters.bucketPolicy | tostring) as $pol
      | (($pol | test("\"Principal\"\\s*:\\s*\"\\*\"")) or ($pol | test("\"AWS\"\\s*:\\s*\"\\*\""))) as $wild
      | (($pol | test("\"StringLike\"")) or ($pol | test("\"ArnLike\""))) as $likeop
      | ($pol | test("aws:Source(Vpce?|Arn|Account|Owner|Ip)")) as $scoped
      # A wildcard operator over a scoping key re-publicises a statement that reads as scoped —
      # AWS'"'"'s own example is "aws:SourceVpc": "vpc-*". A condition present is not reassurance.
      | (if .eventName != "PutBucketPolicy" then "gate-event"
         elif $wild and $scoped and $likeop then "PUBLIC(wildcard in condition)"
         elif $wild and $scoped then "scoped(confirm with policy-status)"
         elif $wild then "PUBLIC(wildcard principal)"
         else "policy write" end) as $verdict
      | "\(.eventTime)  \(.eventName)  \(.userIdentity.arn)  \($verdict)  " +
        "err=\(.errorCode // "none")  bucket=\(.requestParameters.bucketName // "-")  ip=\(.sourceIPAddress)"'
done | sort
```

Read the `err=none` on a `PUBLIC(...)` row as evidence, not just as an outcome: S3 rejects a public
`PutBucketPolicy` while `BlockPublicPolicy` is set, so a success establishes the flag was false at
that instant. If no `gate-event` appears before it, the gate was already down before this window —
which is a longer-standing problem than the alert suggests.

#### Query 2 — Adjudicate: ask AWS whether the bucket is public

```bash
BUCKET="${1:?bucket name from Query 1 required}"

echo "=== AWS'S OWN VERDICT — this is the arbiter, not the statement text ==="
aws s3api get-bucket-policy-status --bucket "$BUCKET" \
  --query 'PolicyStatus.IsPublic' --output text 2>/dev/null || echo "(no bucket policy)"

echo
echo "=== Which statement, and what else the policy grants ==="
aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text 2>/dev/null \
| jq -r '
    # Statement is a single OBJECT when there is exactly one — normalise, or a one-statement policy
    # silently reports clean.
    (if (.Statement | type) == "object" then [.Statement] else .Statement end)[]
    | . as $s
    | [($s.Principal | if type == "string" then [.] else (to_entries[].value
        | if type == "array" then .[] else . end) end)] | flatten as $p
    | if ($p | index("*")) and $s.Effect == "Allow" then
        "[!] WILDCARD Allow  Sid=\($s.Sid // "-")  Action=\($s.Action)  Condition=\($s.Condition // "none")"
      elif $s.Effect == "Allow" then
        "[ ] delegated Allow  Sid=\($s.Sid // "-")  to=\($p | join(","))"
      else empty end'
```

The second block matters as much as the first. AWS: one public statement *"renders the entire policy
public, so `RestrictPublicBuckets` applies. As a result, Amazon S3 disables cross-account access,
even though the policy delegates access to a specific account."* Every `[ ] delegated Allow` row is
an integration that is **already broken** if `RestrictPublicBuckets` is on, and that will be
reported to you as an unrelated outage.

#### Query 3 — Sweep: which other buckets are public right now

```bash
aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n' \
| while read -r B; do
    [ -z "$B" ] && continue
    P="$(aws s3api get-bucket-policy-status --bucket "$B" \
           --query 'PolicyStatus.IsPublic' --output text 2>/dev/null)"
    case "$P" in
      True)     echo "[!] $B — PUBLIC" ;;
      False)    echo "[OK] $B" ;;
      "")       echo "[ ] $B — no bucket policy" ;;
      *)        echo "[?] $B — could not determine ($P)" ;;
    esac
  done
```

Cross-reference every `[!]` against the §1 record of deliberately public buckets. A `[!]` on that
list is expected; one that is not is either a second incident or a pre-existing gap, and separating
those two is what decides the scope of the response.

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

Look for `GetBucketPolicy` and `ListBuckets` **before** the write. A principal that read the policy
first was working out what to preserve; a deployment pipeline does not need to.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Order matters and is counterintuitive. Step 1 restores the guardrail, which is instant and stops
further access — but it does not remove the grant, and it is the step that breaks partner
integrations. Step 2 removes the grant, which is the actual fix.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 2 returns
`IsPublic: True` on a bucket holding production or regulated data, run Step 1 immediately and accept
the collateral in Step 2's warning. Anonymous internet read access is not something to sequence
around; the partner outage is recoverable and the disclosure is not.

#### Step 1 — Restore the gate, at both scopes

```bash
BUCKET="${1:?bucket name required}"
ACCT="$(aws sts get-caller-identity --query Account --output text)"
PAB="BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Account first — AWS applies "the most restrictive combination of the bucket-level and
# account-level settings", so setting the account constrains every bucket at once.
aws s3control put-public-access-block --account-id "$ACCT" \
  --public-access-block-configuration "$PAB" && echo "[OK] account-level block set (all four)"

if aws s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
  aws s3api put-public-access-block --bucket "$BUCKET" \
    --public-access-block-configuration "$PAB" \
    && echo "[OK] bucket block set on $BUCKET (all four)"
else
  echo "[FAIL] bucket $BUCKET not found or not accessible"
fi

echo "[!] The public statement is now SUPPRESSED, not removed. Proceed to Step 2."
```

**Before running the account call:** the floor applies to every bucket, so a legitimately public
bucket in this account goes offline. During an active exposure that is usually the right trade, but
it is a decision rather than a side effect. Note also that an **organization-level** Block Public
Access policy, if one is in force, overrides the account setting entirely — in that case this call
may report success and change nothing.

#### Step 2 — Remove the public statement, and expect collateral

```bash
BUCKET="${1:?bucket name required}"
TS="$(date -u '+%Y%m%dT%H%M%SZ')"
BAK="/tmp/${BUCKET}-policy-${TS}.json"

aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text > "$BAK" 2>/dev/null \
  && echo "[OK] policy preserved at $BAK" || { echo "(no policy)"; exit 0; }

# A bucket policy is frequently the only record of a cross-account arrangement. Non-public
# statements are preserved; only the wildcard Allow is removed.
RESULT="$(jq -c '
  (if (.Statement | type) == "object" then [.Statement] else .Statement end) as $s
  | def pub: .Effect == "Allow" and ([(.Principal | if type == "string" then [.]
      else (to_entries[].value | if type == "array" then .[] else . end) end)]
      | flatten | index("*")) != null;
    {removed: ([$s[] | select(pub)] | length),
     kept:    ([$s[] | select(pub | not)] | length),
     doc:     (. + {Statement: [$s[] | select(pub | not)]})}' "$BAK")"

N="$(printf '%s' "$RESULT" | jq -r '.removed')"
K="$(printf '%s' "$RESULT" | jq -r '.kept')"
if [ "$N" = "0" ]; then
  echo "[OK] no wildcard Allow to remove — the exposure may be by ACL; see ../s3.exfiltration.bucket-acl-configured/"
elif [ "$K" = "0" ]; then
  aws s3api delete-bucket-policy --bucket "$BUCKET" \
    && echo "[OK] policy was entirely public — deleted (backup at $BAK)"
else
  printf '%s' "$RESULT" | jq -r '.doc | tojson' \
    | xargs -0 -I{} aws s3api put-bucket-policy --bucket "$BUCKET" --policy {} \
    && echo "[OK] removed $N public statement(s), kept $K"
fi
```

**Expect a partner outage to be reported now, and expect it to be reported as unrelated.** While the
policy contained a public statement, `RestrictPublicBuckets` was disabling the cross-account access
the *other* statements granted. Removing the public statement is what restores those partners —
Step 1 alone left them broken. If someone opens a ticket about a failing integration within the
hour, this is why.

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
    echo "    Save as revoke.json and attach with put-role-policy:"
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

#### Step 4 — Establish whether the exposure was read

```bash
BUCKET="${1:?bucket name required}"
REGION="${AWS_REGION:-us-east-1}"

aws cloudtrail list-trails --region "$REGION" --query 'Trails[].TrailARN' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r T; do
    [ -z "$T" ] && continue
    aws cloudtrail get-event-selectors --trail-name "$T" --region "$REGION" --output json 2>/dev/null \
    | jq -r --arg t "$T" 'if (tostring | test("AWS::S3::Object"))
                          then "[OK] \($t) records S3 object data events" else empty end'
  done
echo "[!] If nothing printed [OK], reads during the exposure were NEVER recorded. Data events are"
echo "    off by default, billable and not enablable retroactively — absence is not a negative result."
```

---

## 4. Eradication

### Remove Attacker Access

#### Treat the exposure window as full disclosure where reads were not recorded

The window runs from the successful `PutBucketPolicy` to the completion of Step 2. Within it,
anyone on the internet could read every object the statement's `Action` and `Resource` covered.
Step 4 establishes whether that is recorded; where it is not, assume every object in scope was
retrieved and route it down the disclosure path. Reporting "no evidence of access" when no evidence
could have existed is materially misleading in front of a legal or compliance decision.

#### Find out how long the gate had been down

If Query 1 showed the public write succeeding with no gate-lowering event before it, the gate was
already false when the actor arrived — possibly for months. That inverts the incident: the write was
opportunistic, and the finding is a guardrail that has been off across an unknown number of buckets.
Query 3's sweep is the scope of that, and it usually matters more than the single write that
triggered the alert.

#### Close the conditioned-but-public statements too

Query 2's `Condition=` column is where these hide. A statement with `"StringLike": {"aws:SourceVpc":
"vpc-*"}` is public by AWS's evaluation and reads as scoped to a human. Rewriting the operator to
`StringEquals` with a fixed value is the fix, and it is usually a one-character-class change that
nobody notices is load-bearing.

#### Right-size who can write bucket policies

`s3:PutBucketPolicy` belongs to infrastructure automation. Review every identity and resource policy
granting it, and every wildcard (`s3:Put*`, `s3:*`) that grants it by accident. Then set the account
floor and protect it:

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyLoweringTheAccountFloor",
  "Effect": "Deny",
  "Action": ["s3:PutAccountPublicAccessBlock", "s3:DeleteAccountPublicAccessBlock"],
  "Resource": "*",
  "Condition": {"ArnNotLike": {"aws:PrincipalARN": "arn:aws:iam::*:role/YourBreakGlassRole"}}
}
```

Attach it to an OU, not the management account, where SCPs do not apply. `YourBreakGlassRole` must
be a role that genuinely exists — an `ArnNotLike` against a non-existent role denies the action to
everyone including you. Test in a non-production OU first.

---

## 5. Recovery

### Restore Clean State

#### Verify with AWS's evaluator, not by reading the policy

```bash
BUCKET="${1:?bucket name required}"

P="$(aws s3api get-bucket-policy-status --bucket "$BUCKET" \
       --query 'PolicyStatus.IsPublic' --output text 2>/dev/null)"
case "$P" in
  False|"") echo "[OK] $BUCKET is not public" ;;
  True)     echo "[FAIL] $BUCKET is STILL public" ;;
  *)        echo "[!] could not determine ($P)" ;;
esac

# The guardrail can mask a public statement, so check the policy is genuinely clean as well.
aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text 2>/dev/null \
| jq -r '(if (.Statement | type) == "object" then [.Statement] else .Statement end)[]
    | select(.Effect == "Allow")
    | select([(.Principal | if type == "string" then [.] else (to_entries[].value
        | if type == "array" then .[] else . end) end)] | flatten | index("*"))
    | "[FAIL] wildcard Allow still present — Sid=\(.Sid // "-")"'
echo "[OK] if no FAIL printed above, the grant is removed and not merely suppressed"
```

Both checks are needed. `IsPublic: False` with the statement still present means Block Public Access
is masking it — the bucket is one flag away from public again and will pass every audit that reads
only the guardrail.

#### Verify the partners are working again

```bash
BUCKET="${1:?bucket name required}"

# Every delegated Allow was disabled while the policy was public. Removing the public statement
# should have restored them; this lists what should now be working so it can be confirmed with the
# consumers rather than discovered by them.
aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text 2>/dev/null \
| jq -r '(if (.Statement | type) == "object" then [.Statement] else .Statement end)[]
    | select(.Effect == "Allow")
    | [(.Principal | if type == "string" then [.] else (to_entries[].value
        | if type == "array" then .[] else . end) end)] | flatten as $p
    | select(($p | index("*")) | not)
    | "[ ] confirm restored: \($p | join(","))"'
```

#### Verify from outside, unauthenticated

```bash
BUCKET="${1:?bucket name required}"
REGION="$(aws s3api get-bucket-location --bucket "$BUCKET" --query LocationConstraint --output text 2>/dev/null)"
# us-east-1 is reported as "None" by the API, which is not a usable region string.
[ "$REGION" = "None" ] && REGION="us-east-1"

CODE="$(curl -s -o /dev/null -w '%{http_code}' \
          "https://${BUCKET}.s3.${REGION}.amazonaws.com/?list-type=2&max-keys=1")"
case "$CODE" in
  403) echo "[OK] anonymous list denied (403)" ;;
  200) echo "[FAIL] anonymous list SUCCEEDED — still readable from the internet" ;;
  404) echo "[!] 404 — bucket or region wrong; this is not a pass" ;;
  *)   echo "[!] unexpected HTTP $CODE — verify manually" ;;
esac
```

#### Confirm the corrected detection fires

```bash
BUCKET="${1:?disposable test bucket required — do NOT use a production bucket}"

# Exercise the CONDITIONED-BUT-PUBLIC shape, not a bare wildcard: it is the case the source rule
# could not see and the one a human reviewer waves through, so it is the one worth proving. The
# bucket still becomes genuinely public, so this must be a scratch bucket with no objects.
aws s3api put-bucket-policy --bucket "$BUCKET" --policy "$(jq -n --arg b "$BUCKET" '{
  Version: "2012-10-17",
  Statement: [{Sid: "DetectionTest", Effect: "Allow", Principal: "*", Action: "s3:GetObject",
               Resource: "arn:aws:s3:::\($b)/*",
               Condition: {StringLike: {"aws:SourceVpc": "vpc-*"}}}]}')" \
  && echo "[OK] conditioned-public policy written — expect the wildcard-condition rule within 15 min"

sleep 60
aws s3api delete-bucket-policy --bucket "$BUCKET" && echo "[OK] policy removed"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Did the write succeed, and was there a gate-lowering event before it? | A success proves the gate was false at that instant. No preceding gate event means it was already down, which is a much larger finding than the write. |
| Does `GetBucketPolicyStatus` agree with the alert? | The rules over-match by design. If AWS says non-public, the alert was working correctly and the outcome is a tuning note, not a false positive. |
| Was the statement conditioned, and was the operator `StringLike`? | The conditioned-but-public shape is the one that survives review, and finding one means the review process needs the rule rather than the reviewer. |
| Did the policy also delegate to named accounts? | Those were broken for the duration and are the outage nobody will connect to this incident. |
| Were object data events enabled on this bucket? | Decides whether the disclosure question is answerable, and it was settled months ago. |
| How did the principal hold `s3:PutBucketPolicy`? | Usually via an `s3:*` or `s3:Put*` wildcard that nobody intended to include it. |

### Recommended Guardrails

**Set the account-level Block Public Access floor and protect it by SCP.** With `BlockPublicPolicy`
true at the account, S3 refuses the write outright and this playbook's P0 becomes impossible rather
than detectable. Note that an organization-level policy sits above the account and overrides it, so
in an Organizations estate the floor is set there.

**Adjudicate with `GetBucketPolicyStatus` in the alert pipeline, not in the responder's head.**
Enriching each alert with AWS's own verdict removes the entire class of mistake where a
conditioned-but-public statement is closed as scoped.

**Alert on the wildcard-operator shape specifically.** `"StringLike": {"aws:SourceVpc": "vpc-*"}` is
public and reads as scoped. It is the only case here that a competent reviewer will approve, so it
is the one that most needs a machine.

**Never detect public exposure by a vendor-computed boolean.** The source rule's single predicate
was a field its own data source did not produce; it reported clean by construction anywhere the
enrichment was missing. Any rule whose entire logic rests on an enrichment field needs a stated
fallback on the raw event, or it is a rule that cannot be moved.

**Record the cross-account consumers of each bucket policy.** They are the collateral of every
containment action here, and knowing them in advance turns a surprise outage into a notification.

### Technique Reference

**T1530 — Data from Cloud Storage.** Verified live at https://attack.mitre.org/techniques/T1530/ on
2026-08-30. The source rule carried **no** MITRE mapping.

Where the exposure is used to move data to attacker-controlled infrastructure, T1567.002
(Exfiltration to Cloud Storage) applies to that later stage and is not covered here.

AWS references relied on throughout, all verified 2026-08-30:

- The meaning of "public" — the assume-public-then-disprove evaluation, the enumerated condition
  keys, the `"vpc-*"` worked example, the `BlockPublicPolicy` rejection behaviour, and the
  cross-account collateral of a single public statement:
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- `PutBucketPolicy` API reference:
  https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html

Service-wide verified behaviour shared by every `s3.*` playbook is in `../_ground-truth/s3.md`; §6
covers the meaning of "public" and is the basis for the claims above.

### Residual Risk

**The rules cannot reproduce AWS's evaluation, and are not meant to.** They over-match, and every
hit needs `GetBucketPolicyStatus` to resolve. In an estate that writes bucket policies frequently
this is real triage cost, and the alternative — narrowing the rule to only unconditioned wildcards —
would silently drop the conditioned-but-public case that matters most.

**Exposure by ACL is a different path with different evidence.** A bucket can be public through an
ACL grant with no bucket policy at all, and `GetBucketAcl` returns *effective* permissions rather
than the stored ACL, so a suppressed public grant reads as absent. That is
`../s3.exfiltration.bucket-acl-configured/`, and a clean result here does not clear it.

**Access points and CloudFront route around the bucket policy.** An S3 Access Point carries its own
policy, evaluated by slightly different rules — an access point granting `s3:DataAccessPointArn` is
public where the same statement in a bucket policy is not. Neither the CloudTrail rules nor
`GetBucketPolicyStatus` on the bucket covers that.

**Object reads remain invisible where data events are off.** The largest residual gap, and a cost
decision rather than a detection one. It is stated explicitly so that "no evidence of access" is
never reported when no evidence was possible.
