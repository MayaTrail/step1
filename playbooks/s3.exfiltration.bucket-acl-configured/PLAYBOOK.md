# IR Playbook: S3 Bucket ACL Made Public — a predefined-group grant written via `PutBucketAcl`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Collection — a bucket ACL grants to `AllUsers` or `AuthenticatedUsers`, the two predefined groups AWS treats as public, making the bucket readable outside the account |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. Critical when the ACL gate was lowered immediately before, because that pair describes a completed exposure rather than a single ambiguous act. |
| MITRE Tactics | Collection |
| MITRE Techniques | T1530 |
| Services in Scope | S3, IAM, CloudTrail, GuardDuty |

**What the technique does:** the actor writes a bucket ACL granting a permission to `AllUsers` or
`AuthenticatedUsers`. AWS: *"Amazon S3 considers a bucket or object ACL public if it grants any
permissions to members of the predefined `AllUsers` or `AuthenticatedUsers` groups."* If
`BlockPublicAcls` is set, S3 refuses the call — so a successful public ACL write is **evidence that
the flag was false at that instant**, recoverable from the write itself.

**Why the usual reflexes miss it.** The first is to alert on `PutBucketAcl` without reading what it
granted, which is what the source rule does — a continuous P3 stream that gets suppressed, taking
the one call that mattered with it. The second is to read `AuthenticatedUsers` as "authenticated in
our account": it means any principal in **any** AWS account, and anyone who can create an account
qualifies. The third is to resolve the alert by reading the ACL back, which returns *effective*
permissions rather than the stored ACL — a public grant suppressed by `IgnorePublicAcls` reads as
absent and becomes live the moment the flag moves. The fourth is to treat a redacted event as clean:
where another account sets the ACL, AWS removes the grantee detail from the owner's copy, and the
honest verdict there is *undeterminable*.

**Detection thesis:** check the grantee, rate `AuthenticatedUsers` as public, give the redacted
shape its own verdict, and never read an ACL without reading the guardrail alongside it.

**Adjacent playbooks.** Exposure by bucket policy rather than ACL is
`../s3.exfiltration.bucket-policy-made-public/`. The gate being lowered is
`../s3.exfiltration.public-access-block-removed/` and, deleted outright,
`../s3.exfiltration.public-access-block-deleted/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. `PutBucketAcl` is a bucket-level call and therefore a
management event, on by default.

CloudTrail **data events** on buckets holding sensitive data: off by default, billable, not
enablable retroactively. They decide whether "was anything read during the exposure" is answerable,
and that question determines whether this becomes a disclosure.

The Object Ownership setting per bucket. `bucket-owner-enforced` disables ACLs entirely, which makes
every rule here inert on that bucket — correctly, because the technique is impossible there. Knowing
which buckets are in which regime is the difference between "no alerts because it is safe" and "no
alerts because nothing is watching".

**Alerting (must be pre-configured)**

- **ACL gate lowered, then a public ACL written by the same principal within 1h → P0**
- **`PutBucketAcl` grants to `AllUsers` or applies a canned public ACL and succeeds → P0**
- **`PutBucketAcl` grants to `AuthenticatedUsers` — any principal in any AWS account → P0**

**Response Tooling**

An IAM principal that can call `s3api put-bucket-acl`, `get-bucket-acl`,
`get-bucket-ownership-controls` and `put-public-access-block` outside the change pipeline.

`curl` from outside the account. The internal API view and the internet view can disagree, and here
they disagree by construction — `GetBucketAcl` returns enforced permissions, not stored ones.

**Known IOC Baselines**

The list of buckets that are public **on purpose**, shared with the other `s3.*` playbooks.

The roles that own bucket lifecycle, populating `known_provisioners`. An infrastructure apply that
manages a bucket ACL rewrites it on every run.

The accounts that legitimately hold cross-account grants on your buckets. The redacted shape cannot
be resolved from the event, so the list of accounts that are *supposed* to be writing your ACLs is
the only way to triage it quickly.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | ACL gate lowered (`BlockPublicAcls` or `IgnorePublicAcls` false), then a public ACL written by the same principal within 1h | Correlation rule | T1530 |
| P0 | `PutBucketAcl` grants to `AllUsers`, or applies `public-read` / `public-read-write`, and succeeds | CloudTrail | T1530 |
| P0 | `PutBucketAcl` grants to `AuthenticatedUsers` — any principal in any AWS account, which AWS evaluates as public | CloudTrail | T1530 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `PutBucketAcl` succeeds carrying no grantee URI, canned header or `CanonicalUser` — the shape AWS produces when another account sets the ACL | CloudTrail | T1530 |
| P2 | `GetBucketAcl` shows no public grant while `IgnorePublicAcls` is true — a stored grant may be masked rather than absent | API state | T1530 |
| P2 | `PutBucketAcl` on a bucket whose Object Ownership is `bucket-owner-enforced` — the call should fail; a success means the setting changed | CloudTrail | T1530 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| No content check whatsoever | `eventName:"PutBucketAcl" AND NOT _exists_:errorCode` fires identically on an ACL set to `private` and one granting the world read access. In an ACL-managing estate this is a continuous stream, and a continuous P3 is a suppressed P3 — which takes the one call that mattered with it | Match the grantee. AWS's public-ACL definition is exactly two predefined group URIs, so the check costs one `contains` |
| No coverage of the canned-ACL form | An ACL applied via the `x-amz-acl` header carries no grantee URI at all, so any grantee-based rule misses `public-read` entirely | A sibling match on the canned header values, in the same rule |
| Treats `AuthenticatedUsers` as unremarkable | It grants to any principal in **any** AWS account. AWS evaluates it as public and anyone who can create an account qualifies. The name is the trap | Rated identically to `AllUsers`, with its own verdict line in the query so triage does not depend on the responder remembering |
| Collapses "undeterminable" into the same P3 as everything else | Where another account sets the ACL, AWS redacts the grantee from the owner's copy of the event. The correct verdict is that the grant cannot be determined — neither clean nor public | A dedicated low-severity rule for that shape, so it is triaged as its own case rather than disappearing into the stream |
| Rated P3 | This is a direct route to anonymous internet read access, and the same pack rates the bucket-policy route P2. The two are the same exposure by different mechanisms | High for a public grant, critical for the ordered pair with the gate |
| MITRE: none | The pack maps this rule to nothing at all | `T1530 — Data from Cloud Storage` |

**Recommended detection — the grantee check, the undeterminable shape, and the pair with the gate.**

```yaml
# S3 bucket ACL configured to grant public or cross-account access (T1530)
#
# AWS'S DEFINITION OF A PUBLIC ACL IS TWO URIs: "Amazon S3 considers a bucket or object ACL public
# if it grants any permissions to members of the predefined AllUsers or AuthenticatedUsers groups."
# So the content check the source rule omits costs one `contains`.
#
# AuthenticatedUsers is ANY principal in ANY AWS account, not any principal in yours. And neither
# the event nor a live read is authoritative: AWS redacts the grantee on a cross-account write, and
# GetBucketAcl returns ENFORCED rather than stored permissions.
# Full rationale: detections/detection_note_t1530.md.
title: S3 bucket ACL granting to a predefined public group
id: 7a4e91c3-58d2-4b06-9f71-3c0a86e2b5d4
name: s3_bucket_acl_public_grant
status: experimental
description: >-
  A successful PutBucketAcl granting to AllUsers or AuthenticatedUsers, the two predefined groups
  AWS treats as public, or applying a canned public ACL. Because BlockPublicAcls makes S3 reject
  exactly this call when set, a success here is also evidence that the flag was false at that
  moment. AuthenticatedUsers means any principal in any AWS account and is public in the same sense
  as AllUsers.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html
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
    eventName: 'PutBucketAcl'
  success:
    errorCode: null
  # The predefined group URIs are the whole of AWS's public-ACL definition.
  public_group:
    requestParameters|contains:
      - 'acs.amazonaws.com/groups/global/AllUsers'
      - 'acs.amazonaws.com/groups/global/AuthenticatedUsers'
  # The canned-ACL header form carries no grantee URI at all, so it needs its own match.
  canned_public:
    requestParameters.x-amz-acl:
      - 'public-read'
      - 'public-read-write'
      - 'authenticated-read'
  # POPULATE BEFORE DEPLOYING with the roles that own bucket lifecycle.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and (public_group or canned_public) and not known_provisioners
falsepositives:
  - >-
    A bucket deliberately serving public content. It should be on the recorded public-bucket list;
    if it is not, either the list is wrong or the bucket is.
level: high
---
title: S3 bucket ACL written with no readable grantee detail
id: c06b83fa-4719-4e25-8d3b-51fa07c4e6b9
name: s3_bucket_acl_opaque_write
status: experimental
description: >-
  A successful PutBucketAcl whose event carries no grantee URI and no canned-ACL header. This is
  the shape produced when another account sets the ACL — AWS redacts the grantee from the bucket
  owner's copy of the event — and it is also what a malformed or unusual request looks like. The
  correct verdict is that the grant cannot be determined from this event, which is different from
  clean, and different from what a rule matching every PutBucketAcl would report. Requires a live
  read to resolve, and even that is qualified.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html
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
    eventName: 'PutBucketAcl'
  success:
    errorCode: null
  has_grants:
    requestParameters|contains: 'acs.amazonaws.com/groups/global/'
  has_canned:
    requestParameters.x-amz-acl|exists: true
  has_named_grantee:
    requestParameters|contains: 'CanonicalUser'
  condition: selection and success and not (has_grants or has_canned or has_named_grantee)
falsepositives:
  - >-
    An SDK that serialises the ACL differently from what this rule expects. Worth confirming once
    against a known-good request rather than tuning away, because the same shape is what a
    cross-account write looks like.
level: low
---
title: ACL gate lowered and a public ACL then written
id: e5109d7b-2a64-4c83-b0f5-97d3e6a10c28
status: experimental
description: >-
  BlockPublicAcls or IgnorePublicAcls was set false and a public ACL was written afterwards by the
  same principal. This is the sequence BlockPublicAcls exists to make impossible: with it set, S3
  rejects a PutBucketAcl carrying a public ACL, so the gate has to come down first. Critical
  because the two halves together describe a completed exposure where either alone is ambiguous.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
  - https://attack.mitre.org/techniques/T1530/
tags:
  - attack.collection
  - attack.t1530
correlation:
  type: temporal_ordered
  rules:
    - s3_pab_acl_gate_lowered
    - s3_bucket_acl_public_grant
  group-by:
    - userIdentity.arn
  timespan: 1h
level: critical
---
title: S3 Block Public Access ACL gate lowered
id: 4f7c2801-9e56-4a1d-b7e2-08a5c3d69f14
name: s3_pab_acl_gate_lowered
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. BlockPublicAcls or
  IgnorePublicAcls set to false, or the Block Public Access configuration deleted outright, at
  either scope. The rated detections for this act are in
  ../../s3.exfiltration.public-access-block-removed/.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  # Sibling blocks: each is a complete alternative shape of "the ACL gate came down". Within each
  # block the keys are ANDed and they do co-occur on a single event — a PutBucketPublicAccessBlock
  # record carries eventSource, eventName and the submitted flags together.
  block_acls_off:
    eventSource: 's3.amazonaws.com'
    eventName:
      - 'PutBucketPublicAccessBlock'
      - 'PutAccountPublicAccessBlock'
    requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls: false
  ignore_acls_off:
    eventSource: 's3.amazonaws.com'
    eventName:
      - 'PutBucketPublicAccessBlock'
      - 'PutAccountPublicAccessBlock'
    requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls: false
  deleted:
    eventSource: 's3.amazonaws.com'
    eventName:
      - 'DeleteBucketPublicAccessBlock'
      - 'DeleteAccountPublicAccessBlock'
  success:
    errorCode: null
  condition: (block_acls_off or ignore_acls_off or deleted) and success
level: informational
```

What this set structurally cannot do: it cannot resolve a redacted cross-account write from the
event, and a live read will not resolve it either while `IgnorePublicAcls` is masking the result.
And it cannot tell you whether anything was read, because object operations are data events that are
off by default and cannot be enabled retroactively.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

Run Query 1 first; it produces the bucket and principal the rest take as input.

#### Query 1 — Reconstruct: what was granted, to whom, and the gate around it

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in PutBucketAcl PutBucketPublicAccessBlock DeleteBucketPublicAccessBlock; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | (.requestParameters | tostring) as $rp
      | ($rp | test("groups/global/AllUsers")) as $all
      # AuthenticatedUsers is ANY principal in ANY AWS account — not any principal in yours.
      | ($rp | test("groups/global/AuthenticatedUsers")) as $auth
      | (.requestParameters["x-amz-acl"] // "") as $canned
      # No grantee URI, no canned header and no CanonicalUser is the shape AWS produces when
      # another account sets the ACL: the grant is NOT DETERMINABLE from this event.
      | (if .eventName != "PutBucketAcl" then "gate-event"
         elif $all then "PUBLIC(AllUsers)"
         elif $auth then "PUBLIC(AuthenticatedUsers = any AWS account)"
         elif ($canned | test("public-read|public-read-write|authenticated-read")) then "PUBLIC(canned \($canned))"
         elif ($rp | test("CanonicalUser")) then "named grantee"
         else "UNDETERMINABLE(grantee redacted)" end) as $verdict
      | "\(.eventTime)  \(.eventName)  \(.userIdentity.arn)  \($verdict)  " +
        "err=\(.errorCode // "none")  bucket=\(.requestParameters.bucketName // "-")  ip=\(.sourceIPAddress)"'
done | sort
```

`err=none` on a `PUBLIC(...)` row is evidence, not just an outcome: S3 rejects a public
`PutBucketAcl` while `BlockPublicAcls` is set, so a success establishes the flag was false at that
instant. If no `gate-event` precedes it, the gate was already down before this window.

#### Query 2 — Adjudicate: what the ACL grants now, and whether you can trust the answer

```bash
BUCKET="${1:?bucket name from Query 1 required}"

echo "=== Are ACLs even in use on this bucket? ==="
OWN="$(aws s3api get-bucket-ownership-controls --bucket "$BUCKET" \
        --query 'OwnershipControls.Rules[0].ObjectOwnership' --output text 2>/dev/null)"
echo "Object Ownership: ${OWN:-not set}"
[ "$OWN" = "BucketOwnerEnforced" ] && \
  echo "[!] ACLs are DISABLED on this bucket — PutBucketAcl should fail. A success means the setting changed."

echo
echo "=== The guardrail, which decides whether the next answer is trustworthy ==="
IGN="$(aws s3api get-public-access-block --bucket "$BUCKET" \
        --query 'PublicAccessBlockConfiguration.IgnorePublicAcls' --output text 2>/dev/null)"
echo "IgnorePublicAcls: ${IGN:-not set}"

echo
echo "=== Grants as S3 is ENFORCING them (not necessarily as stored) ==="
aws s3api get-bucket-acl --bucket "$BUCKET" --output json 2>/dev/null \
| jq -r '.Grants[]
    | (.Grantee.URI // "") as $u
    | if ($u | test("AllUsers|AuthenticatedUsers"))
      then "[!] PUBLIC — \($u | split("/") | last) -> \(.Permission)"
      else "[ ] \(.Grantee.Type): \(.Grantee.ID // .Grantee.URI // "?") -> \(.Permission)" end'

[ "$IGN" = "True" ] && cat <<'NOTE'

[!] IgnorePublicAcls is TRUE, so the list above is what S3 is ENFORCING, not what is STORED.
    AWS returns "an ACL that reflects the access permissions that Amazon S3 is enforcing, rather
    than the actual ACL that is associated with the bucket." A public grant may be present and
    invisible here, and it becomes live the moment this flag is turned off. Resolve from Query 1's
    event history, and reset the ACL in Step 2 regardless of what this shows.
NOTE
```

The three blocks answer three different questions, and the order matters: whether ACLs apply at all,
whether the read you are about to do is trustworthy, and only then what it says. Skipping to the
third is how a masked public grant gets recorded as clean.

#### Query 3 — Sweep: every bucket's ACL and ownership regime

```bash
aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n' \
| while read -r B; do
    [ -z "$B" ] && continue
    OWN="$(aws s3api get-bucket-ownership-controls --bucket "$B" \
            --query 'OwnershipControls.Rules[0].ObjectOwnership' --output text 2>/dev/null)"
    if [ "$OWN" = "BucketOwnerEnforced" ]; then
      echo "[OK] $B — ACLs disabled (technique not possible here)"
      continue
    fi
    PUB="$(aws s3api get-bucket-acl --bucket "$B" --output json 2>/dev/null \
           | jq -r '[.Grants[] | select(.Grantee.URI // "" | test("AllUsers|AuthenticatedUsers"))]
                    | length')"
    if [ "${PUB:-0}" -gt 0 ]; then
      echo "[!] $B — $PUB public ACL grant(s), ownership=${OWN:-unset}"
    else
      echo "[ ] $B — no enforced public grant, ownership=${OWN:-unset} (may be masked)"
    fi
  done
```

The `[ ]` rows are deliberately not `[OK]`. On a bucket where `IgnorePublicAcls` is true, this sweep
cannot distinguish "no public grant" from "a public grant that is being suppressed", and treating
those as the same is the mistake this playbook exists to prevent.

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

Look for `PutBucketOwnershipControls` in this output. Moving a bucket off `bucket-owner-enforced` is
the prerequisite for the ACL technique on a modern bucket, and it is a quieter call than the ACL
write itself.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Step 1 restores the guardrail, which is instant and stops access. Step 2 resets the ACL, which is
the actual fix — the guardrail suppresses ACL grants and does not remove them.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 1 shows a
`PUBLIC(...)` grant with `err=none` on a bucket holding production or regulated data, run Step 1
immediately. Anonymous internet read access is not something to sequence around.

#### Step 1 — Restore the ACL gate, at both scopes

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

echo "[!] The ACL grant is now SUPPRESSED, not removed — and GetBucketAcl will now hide it."
echo "    Proceed to Step 2 and reset the ACL regardless of what a read shows."
```

That last warning is the difference between this playbook and a generic one. Turning on
`IgnorePublicAcls` makes `GetBucketAcl` stop reporting the public grant, so a responder who verifies
after Step 1 and stops will record a clean result on a bucket that still stores a public ACL.

#### Step 2 — Reset the ACL, unconditionally

```bash
BUCKET="${1:?bucket name required}"
TS="$(date -u '+%Y%m%dT%H%M%SZ')"

# Preserve first. The stored ACL may include legitimate cross-account grants that are not visible
# in a read taken after Step 1, so this capture is best taken from Query 1's event history if
# IgnorePublicAcls is already on.
aws s3api get-bucket-acl --bucket "$BUCKET" --output json 2>/dev/null \
  | tee "/tmp/${BUCKET}-acl-${TS}.json" >/dev/null \
  && echo "[OK] enforced ACL captured at /tmp/${BUCKET}-acl-${TS}.json"

aws s3api put-bucket-acl --bucket "$BUCKET" --acl private \
  && echo "[OK] ACL reset to private — the stored public grant is now gone, not masked"
```

Run this even when Step 1's read showed nothing. The reset is cheap, and the alternative is leaving
a stored public grant behind a flag that a future change will move.

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

The window runs from the successful `PutBucketAcl` to the completion of Step 2. Within it anyone on
the internet — or, for an `AuthenticatedUsers` grant, anyone with any AWS account — could read every
object the permission covered. Step 4 establishes whether that is recorded; where it is not, assume
every object in scope was retrieved and route it down the disclosure path.

#### Move the bucket to `bucket-owner-enforced`

This is the durable fix and it removes the technique rather than detecting it. With Object Ownership
set to `bucket-owner-enforced`, ACLs are disabled on the bucket entirely and no `PutBucketAcl` can
grant anything to anyone:

```bash
BUCKET="${1:?bucket name required}"
aws s3api put-bucket-ownership-controls --bucket "$BUCKET" \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]' \
  && echo "[OK] ACLs disabled on $BUCKET"
```

**Before running this:** any workflow that depends on object ACLs — a cross-account writer granting
`bucket-owner-full-control`, a consumer reading via an object ACL grant — stops working. Query 2's
named-grantee rows are the list of things to check first. On a bucket with no such rows this is
close to free.

#### Resolve every undeterminable write in the window

The redacted cross-account shape cannot be resolved from the event or, once the guardrail is back,
from a read. The only way to close it is against the §1 record of accounts that legitimately hold
grants on your buckets. A write from an account not on that list, with no readable grantee, should
be treated as a public grant until someone can show otherwise — the alternative is closing it as
clean on no evidence.

#### Right-size who can write bucket ACLs

`s3:PutBucketAcl` belongs to infrastructure automation, and on a `bucket-owner-enforced` bucket to
nobody. Review every identity and resource policy granting it, and every wildcard (`s3:Put*`,
`s3:*`) that grants it by accident. Then protect the account floor:

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

#### Verify the ACL is clean, and say why the read is trustworthy

```bash
BUCKET="${1:?bucket name required}"

IGN="$(aws s3api get-public-access-block --bucket "$BUCKET" \
        --query 'PublicAccessBlockConfiguration.IgnorePublicAcls' --output text 2>/dev/null)"

N="$(aws s3api get-bucket-acl --bucket "$BUCKET" --output json 2>/dev/null \
     | jq -r '[.Grants[] | select(.Grantee.URI // "" | test("AllUsers|AuthenticatedUsers"))] | length')"

if [ "${N:-0}" -gt 0 ]; then
  echo "[FAIL] $BUCKET still shows $N public grant(s)"
elif [ "$IGN" = "True" ]; then
  # The read is masked, so a clean result here proves nothing on its own — Step 2's unconditional
  # reset is what makes it trustworthy, and this records that it ran.
  echo "[OK] no public grant enforced, and Step 2 reset the stored ACL — the clean read is backed"
  echo "     by the reset, not by the read alone (IgnorePublicAcls is masking)"
else
  echo "[OK] $BUCKET — no public grant, and IgnorePublicAcls is not masking the result"
fi
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

This does not cover the `AuthenticatedUsers` case: an anonymous request is denied while any AWS
account still has access. To check that one, make the same request signed with credentials from an
unrelated account, or rely on the ACL read above.

#### Confirm the corrected detection fires

```bash
BUCKET="${1:?disposable test bucket required — do NOT use a production bucket}"

# Exercise the AuthenticatedUsers grant rather than AllUsers: it is the one the source rule and
# most reviewers under-read, and it is genuinely public, so this must be a scratch bucket with no
# objects.
aws s3api put-bucket-acl --bucket "$BUCKET" --grant-read \
    'uri=http://acs.amazonaws.com/groups/global/AuthenticatedUsers' \
  && echo "[OK] AuthenticatedUsers grant written — expect a P0, not a low-severity note, within 15 min"

sleep 60
aws s3api put-bucket-acl --bucket "$BUCKET" --acl private && echo "[OK] reset to private"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Was the grant to `AllUsers` or `AuthenticatedUsers`? | Both are public. If the triage notes treat the second as internal, the misreading is the finding and it will recur. |
| Did the write succeed, and was there a gate event before it? | A success proves `BlockPublicAcls` was false at that instant. No preceding gate event means it was already down. |
| Was the grantee readable in the event? | A redacted grantee means another account wrote the ACL, and the response depends on whether that account is on the expected list. |
| Was `IgnorePublicAcls` true when someone read the ACL back? | If so, any clean read taken before Step 2's reset proves nothing, and a report resting on it is wrong. |
| Was the bucket previously `bucket-owner-enforced`? | If so, someone changed Object Ownership first, and that call is the earlier and quieter signal. |
| Were object data events enabled on this bucket? | Decides whether the disclosure question is answerable, and it was settled months ago. |

### Recommended Guardrails

**Set Object Ownership to `bucket-owner-enforced` wherever ACLs are not actively used.** It removes
the technique rather than detecting it: with ACLs disabled, `PutBucketAcl` cannot grant anything to
anyone. This is the single highest-value item here, and on most modern buckets it costs nothing.

**Check the grantee, always.** A rule that alerts on `PutBucketAcl` without reading what it granted
produces a stream that will be suppressed, and AWS's public definition is two URIs — there is no
cost argument for content-blindness.

**Rate `AuthenticatedUsers` as public in tooling, not in training.** Expecting responders to
remember that it means any AWS account is a control that fails under pressure. Put it in the alert
text.

**Never verify an ACL without reading the guardrail.** `GetBucketAcl` returns enforced permissions,
so a clean read taken with `IgnorePublicAcls` on is not evidence. Either check the flag first or
reset the ACL unconditionally, as §3 Step 2 does.

**Set the account-level Block Public Access floor and protect it by SCP.** With `BlockPublicAcls`
true at the account, S3 refuses the write outright and the P0 here becomes impossible rather than
detectable.

### Technique Reference

**T1530 — Data from Cloud Storage.** Verified live at https://attack.mitre.org/techniques/T1530/ on
2026-08-30. The source rule carried **no** MITRE mapping.

AWS references relied on throughout, all verified 2026-08-30:

- The meaning of "public" for ACLs — the `AllUsers` / `AuthenticatedUsers` definition, the
  `BlockPublicAcls` rejection behaviour, and the `GetBucketAcl` effective-permissions caveat:
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
- `PutBucketAcl` API reference, including the canned-ACL header form:
  https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html

Service-wide verified behaviour shared by every `s3.*` playbook is in `../_ground-truth/s3.md`.

### Residual Risk

**The redacted cross-account write cannot be resolved from AWS data.** Where another account sets
the ACL, neither the event nor a live read establishes what was granted. The only resolution is the
§1 list of accounts expected to hold grants, and where that list does not exist the honest verdict
stays *undeterminable* — which is uncomfortable to put in a report and is nonetheless correct.

**A masked grant survives a clean audit.** With `IgnorePublicAcls` on, `GetBucketAcl` reports the
enforced ACL, so a stored public grant is invisible to every review that reads the API. It becomes
live the moment the flag moves, which may be months later and by someone with no knowledge of this
incident. The unconditional reset in Step 2 is the only defence, and it only protects buckets that
were part of a response.

**Object ACLs are a separate surface.** This playbook covers the *bucket* ACL. Individual objects
carry their own ACLs, set by `PutObjectAcl`, which is a **data** event — off by default, so on most
buckets those writes are not recorded at all and no rule here can see them.

**Email-grantee ACLs now fail rather than being suspicious.** AWS discontinued Email Grantee ACLs on
1 October 2025 and such requests receive HTTP 405. Any rule built to catch that form is inert, and
its absence from output means nothing.
