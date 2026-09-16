# IR Playbook: S3 Bucket Policy Deleted — an access control removed via `DeleteBucketPolicy`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Collection or availability impact, and the event cannot say which — a bucket policy is removed, taking with it whatever `Allow` and `Deny` statements it contained |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Medium for one deletion, because the direction of the change is genuinely ambiguous. Critical when one principal deletes policies across three or more buckets in an hour, which is not ambiguous at all. |
| MITRE Tactics | Collection; Impact on the multi-bucket case |
| MITRE Techniques | T1530; T1531 on the multi-bucket case |
| Services in Scope | S3, IAM, CloudTrail |

**What the technique does:** the actor calls `DeleteBucketPolicy`. The event records that a policy
was removed and **not what it said**. A bucket policy can carry `Allow` statements, `Deny`
statements or both, so the same event can mean access widened, access narrowed, or both at once. The
only thing that resolves it is the last `PutBucketPolicy` for that bucket — whose CloudTrail record
carries the full document, and which is frequently the only surviving copy of the policy anywhere.

**Why the usual reflexes miss it.** The first is to read this as an exposure. It is not: public
access requires a wildcard `Allow`, and deleting a policy removes statements and adds none. A
responder who runs the public-bucket procedure finds the bucket is not public, closes the ticket, and
leaves the removed `Deny` statements removed — the transport enforcement, encryption enforcement,
VPC-endpoint restriction and delete protection that are usually implemented nowhere else. The second
is to reason about it like its sibling: a successful *public* `PutBucketPolicy` proves
`BlockPublicPolicy` was false, but `DeleteBucketPolicy` has no such interlock and its success proves
nothing about the guardrail. The third is to rate it P4 as the source rule does, which puts an
irreversible loss of policy text below the threshold at which anyone recovers it in time.

**Detection thesis:** ship the single deletion at medium and reconstruct its direction from the
prior write; rate the multi-bucket case on scale, which is unambiguous; and treat the
deletion-then-public-write pair as its own finding.

**Adjacent playbooks.** The public write that may follow is
`../s3.exfiltration.bucket-policy-made-public/`. Exposure by ACL is
`../s3.exfiltration.bucket-acl-configured/`. The guardrail being lowered is
`../s3.exfiltration.public-access-block-removed/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region, **retained beyond the 90-day `lookup-events`
horizon**. This is the load-bearing prerequisite here and it is not the usual one: the deleted
policy's contents exist only in the prior `PutBucketPolicy` event, so the retention window is
directly the window in which this incident is answerable at all. Past it, the correct verdict
becomes *unknown* and stays there.

A copy of every bucket policy outside AWS — in the IaC repository, or a scheduled export. `Allow`
statements are usually reproducible from IaC; `Deny` statements added by hand after an audit finding
often are not, and those are the ones that matter.

AWS Config with `s3-bucket-policy-not-more-permissive` or an equivalent recorder, which keeps
configuration history independently of CloudTrail retention.

**Alerting (must be pre-configured)**

- **One principal deletes bucket policies across three or more buckets within an hour → P0**
- **A bucket policy is deleted and a public grant is then written to the same bucket by the same principal within 1h → P0**

**Response Tooling**

Read access to CloudTrail history for `PutBucketPolicy`, and the ability to run `lookup-events`
without a change ticket. Recovery here is a log query, not an API call.

An IAM principal that can call `s3api put-bucket-policy` to restore what is recovered.

**Known IOC Baselines**

The roles that own bucket lifecycle, populating `known_provisioners`. An infrastructure apply that
rebuilds a bucket legitimately deletes and rewrites its policy in one run, and without this list the
rule fires on every deploy.

The environment teardown schedule. A teardown legitimately removes many policies at once and is the
only benign explanation for the multi-bucket correlation.

The cross-account consumers of each bucket policy. If the removed policy was their only grant, they
are now failing, and the outage will be reported as unrelated.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | One principal successfully deletes bucket policies on three or more buckets within an hour | Correlation rule | T1531 |
| P0 | A policy is deleted and a public grant is then written to the same bucket by the same principal within 1h | Correlation rule | T1530 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | A deleted policy whose last `PutBucketPolicy` contained `Deny` statements — access widened for every identity already holding IAM-based S3 permissions | CloudTrail join | T1530 |
| P2 | A deleted policy with no prior `PutBucketPolicy` in the retention window — contents unrecoverable, verdict `unknown` rather than clean | CloudTrail join | T1530 |
| P2 | A deleted policy that granted named principals — an availability outage that will arrive as an unrelated ticket | CloudTrail join | T1531 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Reports a directionally ambiguous event as a single outcome | A bucket policy can carry `Allow`, `Deny` or both, so the same event means access widened, narrowed, or both. All three arrive identically at P4 | Reconstruct the direction by joining each deletion to the last preceding `PutBucketPolicy`, whose record carries the document |
| Rated P4 | The removed policy's text survives only in the prior write event, and `lookup-events` serves 90 days. P4 is below the threshold at which anyone recovers it in time, so the rating causes the loss it is reporting | Medium for a single deletion; critical for the multi-bucket case |
| Grouped with public-exposure use cases | Deleting a policy cannot make a bucket public — that needs a wildcard `Allow`, and deletion adds none. The grouping sends the responder to the wrong procedure, where they find nothing and close the ticket | Its own use case, with the exposure case shipped explicitly as a deletion-then-public-write correlation |
| No scale dimension | One deletion is genuinely ambiguous. Three across different buckets by one principal in an hour is not, and that is the case the source's own "impact" framing describes | A `value_count` correlation at three buckets per principal per hour |
| No principal filter | Every infrastructure apply that rebuilds a bucket deletes and rewrites its policy | `known_provisioners`, shipped with placeholders that must be populated |
| MITRE: none | The pack maps this rule to nothing at all | `T1530` for the widen-access outcome; `T1531` on the multi-bucket correlation for the availability outcome. `T1685` was considered and rejected — its description scopes it to security tools and logging, and a bucket policy is neither |

**Recommended detection — the ambiguous single event, the unambiguous scale case, and the pair.**

```yaml
# S3 bucket policy deleted (T1530)
#
# THE EVENT IS DIRECTIONALLY AMBIGUOUS AND CARRIES NO POLICY CONTENT. A bucket policy can contain
# Allow statements, Deny statements or both, so removal can widen access, narrow it, or do both.
# Only the LAST PutBucketPolicy for that bucket resolves it, and CloudTrail's copy of that event is
# frequently the only surviving record of the policy.
#
# It does NOT make the bucket public — that needs a wildcard Allow, and deletion adds none. So the
# severity split is on SCALE, not content. Full rationale: detections/detection_note_t1530.md.
title: S3 bucket policy deleted
id: 8e3f512a-64c7-4d09-bb85-207a1cf3e496
name: s3_bucket_policy_deleted
status: experimental
description: >-
  A successful DeleteBucketPolicy. The direction of the change is not recoverable from this event —
  the removed policy may have been granting access or denying it — so this is shipped as a medium
  that requires the previous PutBucketPolicy to interpret, rather than as a finding in its own
  right. Read it as "an access control whose contents are now only in the event history was
  removed".
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketPolicy.html
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
    eventName: 'DeleteBucketPolicy'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the roles that own bucket lifecycle. An infrastructure apply
  # that rebuilds a bucket legitimately deletes and rewrites its policy in one run.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    A bucket being decommissioned. The bucket deletion that follows shortly after is the
    corroborating evidence, and its absence is what makes a lone deletion worth reading.
level: medium
---
title: S3 bucket policies deleted across multiple buckets by one principal
id: 1a67d0b4-9382-4e15-a7c6-4f80b21de537
status: experimental
description: >-
  One principal successfully deleted the bucket policy on several buckets within an hour. A single
  deletion is ambiguous; this is not. Whatever those policies contained, removing them across a set
  of buckets at once is either a destructive action or an automation fault, and both need a human
  now. This is the shape that justifies the source use case's "impact" framing, which the
  single-event rule it shipped does not.
references:
  - https://attack.mitre.org/techniques/T1530/
  - https://attack.mitre.org/techniques/T1531/
tags:
  - attack.collection
  - attack.impact
  - attack.t1530
  - attack.t1531
correlation:
  type: value_count
  rules:
    - s3_bucket_policy_deleted
  group-by:
    - userIdentity.arn
  timespan: 1h
  condition:
    gte: 3
    field: requestParameters.bucketName
falsepositives:
  - >-
    A teardown of an environment, which legitimately removes many policies at once. It should
    correlate with bucket deletions in the same window; allowlist the teardown role on the base
    rule rather than raising the threshold.
level: critical
---
title: S3 bucket policy deleted and the bucket then opened
id: 5c92b7e0-38f1-4a64-9d27-e60b3a815cf2
status: experimental
description: >-
  A policy was deleted and a public grant was then written to the same bucket by the same
  principal. The deletion on its own does not expose anything — public access requires a wildcard
  Allow, and removing a policy adds none — so this pair is what turns an ambiguous removal into a
  clear sequence: clear the ground, then open the bucket.
references:
  - https://attack.mitre.org/techniques/T1530/
tags:
  - attack.collection
  - attack.t1530
correlation:
  type: temporal_ordered
  rules:
    - s3_bucket_policy_deleted
    - s3_bucket_public_write
  group-by:
    - userIdentity.arn
  timespan: 1h
level: high
---
title: S3 bucket opened by policy or ACL
id: d419a8c6-052b-4f37-8e91-73c60ad5f218
name: s3_bucket_public_write
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. A PutBucketPolicy carrying a
  wildcard principal, or a PutBucketAcl granting to a predefined public group. The rated detections
  for these acts are in ../../s3.exfiltration.bucket-policy-made-public/ and
  ../../s3.exfiltration.bucket-acl-configured/.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  # Sibling blocks: two complete alternative shapes of "the bucket was opened". Within each block
  # the keys are ANDed and they do co-occur on a single event — the record carries eventSource,
  # eventName and the request body together.
  public_policy:
    eventSource: 's3.amazonaws.com'
    eventName: 'PutBucketPolicy'
    requestParameters.bucketPolicy|contains:
      - '"Principal":"*"'
      - '"Principal": "*"'
      - '"AWS":"*"'
      - '"AWS": "*"'
  public_acl:
    eventSource: 's3.amazonaws.com'
    eventName: 'PutBucketAcl'
    requestParameters|contains:
      - 'acs.amazonaws.com/groups/global/AllUsers'
      - 'acs.amazonaws.com/groups/global/AuthenticatedUsers'
  success:
    errorCode: null
  condition: (public_policy or public_acl) and success
level: informational
```

What this set structurally cannot do: it cannot recover a policy whose last write predates the
retention window, and no AWS API returns a deleted policy. Where that is the case the verdict is
*unknown*, permanently, and the response has to be rebuilding the intended controls rather than
restoring the previous ones.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

Run Query 1 first — it is the recovery step, and it is time-limited.

#### Query 1 — Recover the policy that was deleted

```bash
BUCKET="${1:?bucket name from the alert required}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-90d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '90 days ago' '+%Y-%m-%dT%H:%M:%SZ')"
OUT="./recovered-${BUCKET}-policy.json"

# The deleted policy exists only in the LAST PutBucketPolicy before the deletion. No API returns it.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy \
  --start-time "$START" --region "$REGION" --output json 2>/dev/null \
| jq -r --arg b "$BUCKET" '[.Events[].CloudTrailEvent | fromjson
    | select(.errorCode == null) | select(.requestParameters.bucketName == $b)]
    | sort_by(.eventTime) | last
    | if . == null then empty else .requestParameters.bucketPolicy end' > "$OUT"

if [ -s "$OUT" ]; then
  echo "[OK] recovered the last known policy for $BUCKET -> $OUT"
  jq -r '(if (.Statement | type) == "object" then [.Statement] else .Statement end)[]
         | "  \(.Effect)  Sid=\(.Sid // "-")  Action=\(.Action)  Principal=\(.Principal // "-")"' "$OUT"
  # Deny statements are the part nobody else has a copy of. An Allow is usually reproducible from
  # the IaC definition; a Deny added by hand after an audit finding often is not.
  D="$(jq -r '[(if (.Statement | type) == "object" then [.Statement] else .Statement end)[]
              | select(.Effect == "Deny")] | length' "$OUT")"
  echo "[!] the removed policy contained $D Deny statement(s)"
  # A policy that denied s3:PutBucketPolicy could not survive its own deletion.
  grep -q 's3:PutBucketPolicy' "$OUT" && \
    echo "[!] it also protected itself — the set of principals who could make the NEXT change is now larger"
else
  echo "[FAIL] no PutBucketPolicy for $BUCKET in the last 90 days."
  echo "       The removed policy's contents are UNRECOVERABLE from CloudTrail. Check the IaC"
  echo "       repository and AWS Config history; the verdict is 'unknown', not 'clean'."
fi
```

Run this before containment, not after. Everything else in the playbook can wait; this is the only
step with a deadline attached to it, and once the ninety days pass the policy is gone in a way no
later effort recovers.

#### Query 2 — Establish the direction and the scope

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in DeleteBucketPolicy PutBucketPolicy PutBucketAcl; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | (.requestParameters | tostring) as $rp
      # A public write AFTER a deletion is the pair that turns an ambiguous removal into a sequence.
      | (if .eventName == "DeleteBucketPolicy" then "DELETED"
         elif ($rp | test("\"Principal\"\\s*:\\s*\"\\*\"")) or ($rp | test("groups/global/AllUsers"))
           then "PUBLIC-WRITE"
         else "write" end) as $what
      | "\(.eventTime)  \($what)  \(.userIdentity.arn)  bucket=\(.requestParameters.bucketName // "-")  ip=\(.sourceIPAddress)"'
done | sort
```

Count the distinct buckets on `DELETED` rows for one ARN within an hour. Three or more is the
critical case and needs no further interpretation. A `PUBLIC-WRITE` following a `DELETED` on the
same bucket is the exposure pair, and it is the only shape here that puts data at risk.

#### Query 3 — Which buckets now have no policy at all

```bash
aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n' \
| while read -r B; do
    [ -z "$B" ] && continue
    if aws s3api get-bucket-policy --bucket "$B" >/dev/null 2>&1; then
      echo "[ ] $B — has a policy"
    else
      # No policy is not automatically wrong — many buckets never had one. It is wrong for a bucket
      # that is supposed to enforce transport, encryption or endpoint restrictions in its policy.
      echo "[!] $B — NO bucket policy"
    fi
  done
```

The `[!]` rows are a superset of the incident: most of them are buckets that never had a policy. The
useful comparison is against the §1 export or the IaC repository, which is what says whether a
missing policy is a gap or a design.

#### Query 4 — Full session reconstruction of the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 2 required}"
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

Look for `GetBucketPolicy` before the deletion. A principal that read the policy first knew what it
was removing; a teardown script does not need to.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Recovery comes before containment here, which is unusual and deliberate. The deleted policy's text
is on a ninety-day clock and nothing else in this playbook is. Run §2 Query 1, then contain.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 2 shows a
`PUBLIC-WRITE` following the deletion, this is an active exposure rather than an ambiguous removal:
go to `../s3.exfiltration.bucket-policy-made-public/` and contain that first. If it shows deletions
across three or more buckets, treat it as an in-progress destructive action and contain the
principal before recovering anything.

#### Step 1 — Restore the recovered policy

```bash
BUCKET="${1:?bucket name required}"
POLICY="${2:-./recovered-${BUCKET}-policy.json}"

if [ ! -s "$POLICY" ]; then
  echo "[FAIL] no recovered policy at $POLICY — run §2 Query 1 first"
  exit 1
fi

# Never restore a recovered policy blind: the policy that was deleted may itself have been the
# attacker's, or may have been public. Check before putting it back.
if jq -e '[(if (.Statement | type) == "object" then [.Statement] else .Statement end)[]
           | select(.Effect == "Allow")
           | select([(.Principal | if type == "string" then [.] else (to_entries[].value
               | if type == "array" then .[] else . end) end)] | flatten | index("*"))]
          | length > 0' "$POLICY" >/dev/null 2>&1; then
  echo "[FAIL] the recovered policy contains a WILDCARD ALLOW — restoring it would make the bucket"
  echo "       public. The deletion may have been a remediation. Review before restoring."
  exit 1
fi

aws s3api put-bucket-policy --bucket "$BUCKET" --policy "file://${POLICY}" \
  && echo "[OK] policy restored on $BUCKET"
```

The guard is the point of this step. Deleting a public policy is a *remediation*, and this playbook
fires on it identically — restoring the recovered document without checking would re-expose the
bucket in the name of incident response.

#### Step 2 — Re-apply the protections that are not in the policy

```bash
BUCKET="${1:?bucket name required}"
ACCT="$(aws sts get-caller-identity --query Account --output text)"
PAB="BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# The removed Deny statements are gone until Step 1 restores them, and Step 1 may not be possible.
# Block Public Access is an independent control that does not depend on the policy at all, so it
# can be set now regardless of whether the policy was recovered.
aws s3control put-public-access-block --account-id "$ACCT" \
  --public-access-block-configuration "$PAB" && echo "[OK] account-level block set (all four)"
aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration "$PAB" && echo "[OK] bucket block set (all four)"

# Deny statements commonly implemented ONLY in the bucket policy — check which of these the
# recovered document contained, and re-apply any that cannot be restored with it.
echo "[!] Verify these are still enforced somewhere: aws:SecureTransport denial,"
echo "    s3:x-amz-server-side-encryption requirement, aws:SourceVpce restriction,"
echo "    s3:DeleteObject / s3:DeleteBucket denial."
```

#### Step 3 — Contain the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 2 required}"

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

#### Step 4 — Notify the consumers whose access went with the policy

Query 1's recovered document lists the named principals the policy granted. Each of those is an
integration that stopped working at the moment of deletion, and each will otherwise arrive as an
unrelated ticket some hours later. Notifying them now is cheaper than correlating the outages
afterwards, and it is also how you find out whether the grant was legitimate — a consumer nobody
recognises is a finding of its own.

---

## 4. Eradication

### Remove Attacker Access

#### Establish what protection was actually lost

The recovered document is the evidence. Work through its `Deny` statements specifically: those are
the controls with no other implementation, and they are what the deletion actually removed. An
`Allow` that is gone is usually reproducible from the IaC definition and shows up as a broken
integration; a `Deny` that is gone shows up as nothing at all, which is why it needs to be checked
deliberately rather than waited for.

#### Where the policy is unrecoverable, rebuild rather than restore

If Query 1 found no prior write, the contents are gone. Do not record this as clean. Rebuild the
bucket's intended controls from the IaC definition and the organisation's baseline, and note in the
report that the pre-deletion state is unknown — a policy that had been hardened after an audit
finding may have carried statements nobody remembers.

#### Close the exposure if there was one

If a public write followed the deletion, the exposure is that write and not the deletion. Run
`../s3.exfiltration.bucket-policy-made-public/` §3 and §4 for it, including the data-events question
— whether anything was read during the window is answerable only where data events were already on.

#### Restrict who can delete bucket policies

`s3:DeleteBucketPolicy` belongs to infrastructure automation and to nobody else. Review every
identity policy granting it, and every wildcard (`s3:Delete*`, `s3:*`) that grants it by accident.
Then deny it outside the provisioning path:

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyBucketPolicyDeletion",
  "Effect": "Deny",
  "Action": ["s3:DeleteBucketPolicy"],
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

---

## 5. Recovery

### Restore Clean State

#### Verify the policy is back and is what it should be

```bash
BUCKET="${1:?bucket name required}"

if ! aws s3api get-bucket-policy --bucket "$BUCKET" >/dev/null 2>&1; then
  echo "[FAIL] $BUCKET still has no bucket policy"
  exit 1
fi

aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text 2>/dev/null \
| jq -r '(if (.Statement | type) == "object" then [.Statement] else .Statement end) as $s
    | "[OK] policy present — \($s | length) statement(s), \([$s[] | select(.Effect == "Deny")] | length) Deny"'

# The restored policy must not be public, whatever the recovered document said.
aws s3api get-bucket-policy-status --bucket "$BUCKET" \
  --query 'PolicyStatus.IsPublic' --output text 2>/dev/null \
| while read -r P; do
    case "$P" in
      False) echo "[OK] restored policy is not public" ;;
      True)  echo "[FAIL] the restored policy is PUBLIC — this is worse than the deletion" ;;
      *)     echo "[!] could not determine ($P)" ;;
    esac
  done
```

The `Deny` count is the number that matters. A restoration that brings back the `Allow` statements
and drops the `Deny` statements looks successful and is not, and it is the likely outcome of
rebuilding from IaC where the denies were added by hand.

#### Verify the controls the policy enforced are actually enforced

```bash
BUCKET="${1:?bucket name required}"

# Transport enforcement is the easiest of the common Deny statements to test end to end.
CODE="$(curl -s -o /dev/null -w '%{http_code}' "http://${BUCKET}.s3.amazonaws.com/" 2>/dev/null)"
echo "plain-HTTP request returned $CODE (a 403 is expected where aws:SecureTransport is denied)"

aws s3api get-bucket-encryption --bucket "$BUCKET" \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
  --output text 2>/dev/null || echo "[!] no default encryption configured"

aws s3api get-public-access-block --bucket "$BUCKET" \
  --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null \
| jq -r 'to_entries | map(select(.value != true) | .key) as $off
         | if ($off | length) == 0 then "[OK] all four Block Public Access flags set"
           else "[FAIL] not set: \($off | join(","))" end'
```

#### Confirm the corrected detection fires

```bash
BUCKET="${1:?disposable test bucket required — do NOT use a production bucket}"

# Exercise the deletion on a bucket carrying a Deny-only policy, so the join in the KQL has
# something to reconstruct and the "WIDENS ACCESS" verdict is what should arrive — not a bare P4.
aws s3api put-bucket-policy --bucket "$BUCKET" --policy "$(jq -n --arg b "$BUCKET" '{
  Version: "2012-10-17",
  Statement: [{Sid: "DetectionTestDenyInsecureTransport", Effect: "Deny", Principal: "*",
               Action: "s3:*", Resource: ["arn:aws:s3:::\($b)", "arn:aws:s3:::\($b)/*"],
               Condition: {Bool: {"aws:SecureTransport": "false"}}}]}')" \
  && echo "[OK] Deny-only policy written"

sleep 30
aws s3api delete-bucket-policy --bucket "$BUCKET" \
  && echo "[OK] deleted — expect a medium with a 'WIDENS ACCESS' verdict, not an unclassified P4"
```

Note that the Deny-only policy above is genuinely non-public, so nothing is exposed at any point in
this test — which is what makes it safe to run and still representative.

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Was the removed policy recovered, and how close to the 90-day limit was it? | Recovery is the only time-limited step. If it was close, the retention window is the finding, not the deletion. |
| Did the removed policy contain `Deny` statements, and are they implemented anywhere else? | Those are the controls with no other copy, and they fail silently. |
| Did a public write follow the deletion? | That is the exposure. The deletion alone is not one. |
| How many buckets did this principal touch in the window? | Three or more is a destructive action and not an ambiguous single event. |
| Did the policy protect itself by denying `s3:PutBucketPolicy`? | If so, the set of principals who could make the next change is now larger than before, and larger than an IAM review will show. |
| Which consumers lost access, and were they all recognised? | A grant to a principal nobody recognises is a separate finding that this incident surfaced by accident. |

### Recommended Guardrails

**Export bucket policies on a schedule, outside AWS.** This is the highest-value item and the
cheapest. The whole difficulty of this incident is that the deleted policy exists only in a
CloudTrail event with a ninety-day life; a nightly export removes the deadline entirely.

**Extend CloudTrail retention past 90 days, deliberately.** `lookup-events` is the recovery path and
its horizon is the horizon of the response. Where the trail's S3 objects are the fallback, their
lifecycle policy is doing security work that nobody has written down.

**Deny `s3:DeleteBucketPolicy` outside the provisioning path** with the SCP fragment in §4. There is
no operational reason for a human or an application role to hold it.

**Do not group this with public-exposure detections.** Deleting a policy cannot make a bucket
public, and the grouping sends the responder to a procedure that finds nothing — after which the
removed `Deny` statements stay removed. It is the aggregation that causes the miss, not the rule.

**Alert on scale as well as on the event.** One deletion is ambiguous enough that a busy team will
close it. Three in an hour by one principal is unambiguous, and it is the shape that a rule reporting
single events at P4 will never surface.

### Technique Reference

**T1530 — Data from Cloud Storage.** Verified live at https://attack.mitre.org/techniques/T1530/ on
2026-08-30. This is the mapping for the widen-access outcome: removing `Deny` statements enlarges
the set of principals that can reach the objects, and reaching the objects is the objective.

**T1531 — Account Access Removal** is tagged on the multi-bucket correlation for the availability
outcome. It is the closest available fit rather than an exact one: the technique is written for
identity accounts, and what happens here is access removed at the resource. Stated rather than
smoothed over, because a reader checking the mapping should find the reservation already recorded.

**T1685 — Disable or Modify Tools** was considered and **rejected**. Its description scopes it to
security tools, logging agents and telemetry — *"endpoint detection and response (EDR) tools,
intrusion detection systems (IDS), antivirus, logging agents, sensors"* — and a bucket policy is
none of those. Verified live 2026-08-30, and still the wrong technique.

The source rule carried **no** MITRE mapping.

AWS references relied on throughout, all verified 2026-08-30:

- `DeleteBucketPolicy` API reference:
  https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketPolicy.html
- S3 CloudTrail event names:
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html

Service-wide verified behaviour shared by every `s3.*` playbook is in `../_ground-truth/s3.md`.

### Residual Risk

**A policy older than the retention window is unrecoverable, permanently.** No AWS API returns a
deleted bucket policy. Where the last `PutBucketPolicy` has aged out, the pre-deletion state is
unknown and the response is a rebuild from intent rather than a restoration. The scheduled export in
§6 is the only thing that removes this risk, and it has to be running before the incident.

**A rebuild from IaC quietly drops hand-added `Deny` statements.** Denies added after an audit
finding, or during a previous incident, are frequently not in the IaC definition. A restoration that
looks complete can therefore be missing exactly the controls that mattered most, and nothing in the
verification will show it except counting the `Deny` statements against the recovered document.

**The deletion may have been the remediation.** Removing a public policy is the correct response to
an exposure, and it produces this alert identically. §3 Step 1 guards against restoring a
wildcard-`Allow` document, but a policy that was public through a conditioned statement will pass
that guard — `GetBucketPolicyStatus` after restoration is what catches it.

**Object-level and access-point policies are out of scope.** An S3 Access Point carries its own
policy, deleted by a different call, and neither the rules here nor the recovery query covers it.
A bucket with no bucket policy can still be reachable through an access point that has one.
