# IR Playbook: S3 Block Public Access Weakened — a flag set to `false` via `PutBucketPublicAccessBlock`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Collection — a Block Public Access flag is lowered, either exposing an existing public configuration or removing the refusal that would have blocked the next one |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High when an immediate-effect flag is lowered, medium for a prospective one, critical at account scope. The source rule ORs all four flags at one severity, which is the defect this playbook is built around. |
| MITRE Tactics | Collection |
| MITRE Techniques | T1530 |
| Services in Scope | S3, IAM, CloudTrail, GuardDuty |

**What the technique does:** the actor calls `PutBucketPublicAccessBlock` submitting one or more of
the four flags as `false`. Which flag decides everything, because AWS defines two of them against
the **existing** configuration and two against **future** writes:

| Flag set to `false` | What changes | Urgency |
|---|---|---|
| `RestrictPublicBuckets` | An existing public policy becomes **effective again** | Immediate — data may be public now |
| `IgnorePublicAcls` | Existing public ACLs **take effect again** | Immediate — data may be public now |
| `BlockPublicPolicy` | S3 will now **accept** a public policy on the next write | Prospective — a window remains |
| `BlockPublicAcls` | S3 will now **accept** a public ACL on the next write | Prospective — a window remains |

**Why the usual reflexes miss it.** The first is to treat "Block Public Access was weakened" as one
event, which is what the source rule does — the responder then cannot tell an exposure from an
unlocked door, and those have different first actions. The second is to read the bucket event in
isolation, when the account-level setting is the floor: AWS applies *"the most restrictive
combination of the bucket-level and account-level settings"*, so a bucket flag set false is inert
while the account block holds it true. The third is to restore the flag and close the ticket, when
the flag only masks a public policy that is still sitting in the bucket.

**Detection thesis:** split the alert by flag effect, rate account scope above both, and correlate a
lowered prospective flag with the write it was there to refuse.

**Adjacent playbooks.** The whole configuration deleted rather than a flag lowered is
`../s3.exfiltration.public-access-block-deleted/`. Exposure written where the block was never in the
way is `../s3.exfiltration.bucket-policy-made-public/` and `../s3.exfiltration.bucket-acl-configured/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region, which is where all four events in this playbook live —
S3 *bucket-level* calls are management events and on by default.

S3 *object* calls (`GetObject`, `ListObjects`) are **data events**: off by default, billable, and
**not enablable retroactively**. Without them §2 Query 4 returns nothing whether or not data left,
and "what was read" is permanently unanswerable for the exposure window. Decide which buckets carry
that cost now.

AWS Config with `s3-bucket-level-public-access-prohibited` and
`s3-account-level-public-access-blocks` gives you the *state* to compare against, which CloudTrail
alone does not — the event says what was requested, not what the configuration now is.

**Alerting (must be pre-configured)**

- **`PutAccountPublicAccessBlock` succeeds with any flag `false` → P0**
- **`PutBucketPublicAccessBlock` sets `RestrictPublicBuckets` or `IgnorePublicAcls` `false` on a bucket already public → P0**
- **A prospective flag lowered, then a policy or ACL written by the same principal within 1h → P0**

**Response Tooling**

An IAM principal that can call `s3api put-public-access-block`, `s3control
put-public-access-block`, `s3api put-bucket-policy` and `s3api put-bucket-acl` without going through
the change pipeline — containment here is measured in minutes and the pipeline is not.

`curl` from outside the account. The internal API view and the internet view can disagree, and only
one of them answers the disclosure question.

**Known IOC Baselines**

The list of buckets that are public **on purpose** — static sites, public datasets, CDN origins.
Without it every alert here is ambiguous. Keep it as data a query can join against, not as
institutional memory.

The roles that own bucket lifecycle, which populate `known_provisioners` in the shipped rules. The
rules ship with placeholders; deploy them unpopulated and they alert on every infrastructure apply.

The account-level Block Public Access state, recorded and monitored. It is the floor, and while it
is set most bucket-level events in this playbook are misconfiguration rather than exposure.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `PutAccountPublicAccessBlock` succeeds with any flag `false` — the account floor is lowered and every bucket falls to its own configuration | CloudTrail | T1530 |
| P0 | `PutBucketPublicAccessBlock` sets `RestrictPublicBuckets` or `IgnorePublicAcls` to `false` on a bucket whose policy status is already public | CloudTrail + `get-bucket-policy-status` | T1530 |
| P0 | A prospective flag is lowered and `PutBucketPolicy` or `PutBucketAcl` follows from the same principal within the hour | Correlation rule | T1530 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `BlockPublicPolicy` or `BlockPublicAcls` set `false` with no policy or ACL write yet — the gate is open, nothing is exposed | CloudTrail | T1530 |
| P2 | `RestrictPublicBuckets` or `IgnorePublicAcls` set `false` on a bucket with no public configuration — no exposure, but the protection against one is gone | CloudTrail | T1530 |
| P2 | A partial configuration submitted — fewer than four flags present in the request | CloudTrail | T1530 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| ORs all four flags at one severity | `RestrictPublicBuckets: false` can expose data with no second call; `BlockPublicPolicy: false` exposes nothing and leaves a window. Reported identically, the responder cannot tell which they have, and the first action differs | Two rules split by effect — high for the immediate-effect pair, medium for the prospective pair |
| No account-scope coverage | `PutAccountPublicAccessBlock` is a different event name, and the account setting is the floor for every bucket. One call weakens the whole account and no bucket-scoped rule sees it | A dedicated rule at critical, rated above the bucket cases |
| Requires a flag to be present and `false` | All four are `Required: No`, so a request may carry any subset. AWS does not document merge-versus-replace for a partial document, so the resulting state is not derivable from the event at all | The rules read what is present and never infer absence; §2 Query 2 reads `get-public-access-block` for the actual state |
| Treats the weakening as the whole event | For the prospective flags nothing is public yet — the exposure is the write that follows. Alerting on the flag alone gives no blast radius | A `temporal_ordered` correlation pairing the lowered gate with the policy or ACL write |
| No principal filter | In an IaC estate every bucket apply rewrites this configuration, so an unfiltered rule fires on routine deploys | `known_provisioners` on both bucket rules, shipped with placeholders that must be populated |
| MITRE: none | The pack maps this rule to nothing at all | `T1530 — Data from Cloud Storage` |

**The one thing the source rule got right, and its sibling did not:** the event name.
`PutBucketPublicAccessBlock` **is** what CloudTrail emits — the API operation is
`PutPublicAccessBlock`, and AWS documents that the two differ. The delete-side rule in the same
source pack matched the API name and could never fire. The divergence is per-operation; being right
about one implies nothing about the next.

**Recommended detection — the two flag classes, account scope, and the pair.**

```yaml
# S3 Block Public Access weakened by flag (T1530)
#
# THE FOUR FLAGS ARE NOT INTERCHANGEABLE AND THE SOURCE RULE ORs THEM AS IF THEY WERE.
# RestrictPublicBuckets and IgnorePublicAcls change how an EXISTING configuration is evaluated, so
# data can be public immediately. BlockPublicPolicy and BlockPublicAcls only refuse a FUTURE write.
# One rule reporting all four identically cannot tell a responder which they have.
#
# All four are `Required: No`, so these rules read what is present and never infer absence. And the
# account setting is the floor — AWS applies "the most restrictive combination" — so a bucket flag
# set false is inert while the account block holds it true.
# Full rationale: detections/detection_note_t1530.md.
title: S3 Block Public Access weakened so an existing public configuration takes effect
id: 9f27b054-6e18-41a3-b8c7-2d05e69a4713
name: s3_pab_weakened_immediate
status: experimental
description: >-
  RestrictPublicBuckets or IgnorePublicAcls set to false. These two change how an EXISTING
  configuration is evaluated, so if the bucket already carries a public policy or ACL it becomes
  effective the moment this call succeeds — no second act required.
references:
  - https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html
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
    eventName: 'PutBucketPublicAccessBlock'
  success:
    errorCode: null
  restrict_off:
    requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets: false
  ignore_acls_off:
    requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls: false
  # POPULATE BEFORE DEPLOYING with the roles that own bucket lifecycle.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and (restrict_off or ignore_acls_off) and not known_provisioners
falsepositives:
  - >-
    A bucket deliberately serving public content, where these flags are false by design. It should
    be on the recorded public-bucket list; if it is not, the list is wrong or the bucket is.
level: high
---
title: S3 Block Public Access weakened so a public configuration may be written
id: 3c8e1d97-40ba-4276-95f1-c8047b62ae30
name: s3_pab_weakened_prospective
status: experimental
description: >-
  BlockPublicPolicy or BlockPublicAcls set to false. Neither exposes anything on its own — AWS
  states these flags "doesn't affect existing policies or ACLs" — but they are the refusal, so the
  next public PutBucketPolicy or PutBucketAcl will now succeed. Shipped apart from the
  immediate-effect flags because a window still remains.
references:
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
    eventName: 'PutBucketPublicAccessBlock'
  success:
    errorCode: null
  block_policy_off:
    requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy: false
  block_acls_off:
    requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls: false
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and (block_policy_off or block_acls_off) and not known_provisioners
falsepositives:
  - >-
    A bucket being prepared for public hosting, where the gate is lowered before the policy is
    written. The correlation below is what turns that into a finding when no policy follows.
level: medium
---
title: S3 account-level Block Public Access weakened
id: e40726ba-15c9-4d83-a071-58b6c3e29f14
name: s3_account_pab_weakened
status: experimental
description: >-
  PutAccountPublicAccessBlock set any flag to false. The account setting is the floor for every
  bucket — AWS applies "the most restrictive combination of the bucket-level and account-level
  settings" — so lowering it lets every bucket fall to its own configuration in one call, under an
  event name no bucket-scoped rule matches.
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
    eventName: 'PutAccountPublicAccessBlock'
  success:
    errorCode: null
  restrict_off:
    requestParameters.PublicAccessBlockConfiguration.RestrictPublicBuckets: false
  policy_off:
    requestParameters.PublicAccessBlockConfiguration.BlockPublicPolicy: false
  acls_off:
    requestParameters.PublicAccessBlockConfiguration.BlockPublicAcls: false
  ignore_off:
    requestParameters.PublicAccessBlockConfiguration.IgnorePublicAcls: false
  condition: selection and success and (restrict_off or policy_off or acls_off or ignore_off)
falsepositives:
  - >-
    An account genuinely repurposed for public static hosting. Rare, and it should be a recorded
    decision rather than a tuning exception.
level: critical
---
title: Block Public Access lowered and then the bucket opened
id: 6b91af38-c750-4e24-83db-1f7052ce9a46
status: experimental
description: >-
  A prospective flag was lowered and a policy or ACL written afterwards by the same principal. This
  is the pair the flag exists to prevent: with BlockPublicPolicy true the write is refused, so an
  actor has to lower the gate first. The ordering carries the signal — the reverse order is a
  bucket being locked down. group-by is the principal, because the bucket name is not carried
  identically across both event shapes.
references:
  - https://attack.mitre.org/techniques/T1530/
tags:
  - attack.collection
  - attack.t1530
correlation:
  type: temporal_ordered
  rules:
    - s3_pab_weakened_prospective
    - s3_bucket_open_write
  group-by:
    - userIdentity.arn
  timespan: 1h
level: critical
---
title: S3 bucket policy or ACL written
id: 82d5401e-73fc-4b96-a8e0-950dc17e2f64
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

What this set structurally cannot do: it cannot tell you whether anything was read, because object
operations are data events that are off by default and cannot be enabled retroactively. And for an
ACL set by another account it cannot tell you what was granted — AWS redacts the grantee from the
bucket owner's copy of the event.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.

Run Query 1 first; it produces the principal and bucket the rest take as input.

#### Query 1 — Reconstruct: which flag, at which scope, and what followed

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in PutBucketPublicAccessBlock PutAccountPublicAccessBlock PutBucketPolicy PutBucketAcl; do
  echo "=== $EVT ==="
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | . as $e
      | (.requestParameters.PublicAccessBlockConfiguration // {}) as $p
      # All four flags are Required: No. Absent is NOT false — AWS does not document whether an
      # omitted flag is cleared or preserved — so absence prints "-" and is never read as a
      # weakening. Query 2 reads the resulting state directly.
      | [($p.RestrictPublicBuckets), ($p.IgnorePublicAcls),
         ($p.BlockPublicPolicy), ($p.BlockPublicAcls)]
        | map(if . == null then "-" else tostring end) as $f
      | (if ($f[0] == "false" or $f[1] == "false") then "IMMEDIATE"
         elif ($f[2] == "false" or $f[3] == "false") then "gate-open"
         else "" end) as $mark
      | "\($e.eventTime)  \($e.eventName)  \($e.userIdentity.arn)  " +
        "r=\($f[0]) i=\($f[1]) p=\($f[2]) a=\($f[3])  \($mark)  " +
        "bucket=\($e.requestParameters.bucketName // "-")  ip=\($e.sourceIPAddress)"'
done
```

`IMMEDIATE` means an existing public configuration may already be effective — go straight to Query
3. `gate-open` means no exposure yet and a window remains. A `-` means the request omitted that
flag, so the resulting state is not derivable here.

#### Query 2 — Sweep: the live block state of the account and every bucket

```bash
ACCT="$(aws sts get-caller-identity --query Account --output text)"

echo "=== ACCOUNT FLOOR (constrains every bucket below) ==="
aws s3control get-public-access-block --account-id "$ACCT" \
  --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null \
  || echo "[!] NO ACCOUNT-LEVEL BLOCK — every bucket is on its own configuration"

echo
aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n' \
| while read -r B; do
    [ -z "$B" ] && continue
    CFG="$(aws s3api get-public-access-block --bucket "$B" \
             --query 'PublicAccessBlockConfiguration' --output json 2>/dev/null)"
    if [ -z "$CFG" ]; then
      echo "[!] $B — no bucket-level block (account floor is the only protection)"
      continue
    fi
    printf '%s' "$CFG" | jq -r --arg b "$B" '
      [to_entries[] | select(.value == false) | .key] as $off
      | if ($off | length) == 0 then "[OK] \($b) — all four set"
        else "[!] \($b) — \($off | join(",")) off (" +
             (if (($off | index("RestrictPublicBuckets")) or ($off | index("IgnorePublicAcls")))
              then "IMMEDIATE-EFFECT" else "prospective" end) + ")"
        end'
  done
```

Read the account line first. Any flag true there overrides every bucket below it, so a bucket
flagged `[!]` under a true account flag is misconfigured but not exposed.

#### Query 3 — Inspect: is the bucket public right now

```bash
BUCKET="${1:?bucket name from Query 1 required}"

echo "=== AWS's own verdict ==="
aws s3api get-bucket-policy-status --bucket "$BUCKET" \
  --query 'PolicyStatus.IsPublic' --output text 2>/dev/null || echo "(no bucket policy)"

echo
echo "=== Statements granting to everyone ==="
aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text 2>/dev/null \
| jq -r '
    # Statement is a single OBJECT when there is exactly one — normalise, or a one-statement
    # policy silently reports clean. Principal is "*", {"AWS":"*"} or {"AWS":[...]}.
    (if (.Statement | type) == "object" then [.Statement] else .Statement end)[]
    | select(.Effect == "Allow")
    | select([(.Principal | if type == "string" then [.] else (to_entries[].value
        | if type == "array" then .[] else . end) end)] | flatten | index("*"))
    | "[!] PUBLIC Allow — Sid=\(.Sid // "-") Action=\(.Action)"'

echo
echo "=== ACL grants to predefined public groups ==="
aws s3api get-bucket-acl --bucket "$BUCKET" --output json 2>/dev/null \
| jq -r '.Grants[] | select(.Grantee.URI // "" | test("AllUsers|AuthenticatedUsers"))
         | "[!] PUBLIC ACL grant — \(.Grantee.URI | split("/") | last) -> \(.Permission)"'
```

`get-bucket-policy-status` is AWS's own evaluation and it is the answer; the statement walk exists
to show which statement Step 3 will remove. The ACL section reads live configuration because
cross-account grantee detail is redacted from the owner's trail — there is no history to read.

#### Query 4 — Was anything read, and what else did the principal do

```bash
BUCKET="${1:?bucket name required}"
PRINCIPAL="${2:?principal ARN from Query 1 required}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

echo "=== Does any trail record S3 object data events? ==="
aws cloudtrail list-trails --region "$REGION" --query 'Trails[].TrailARN' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r T; do
    [ -z "$T" ] && continue
    aws cloudtrail get-event-selectors --trail-name "$T" --region "$REGION" --output json 2>/dev/null \
    | jq -r --arg t "$T" 'if (tostring | test("AWS::S3::Object"))
                          then "[OK] \($t) records S3 object data events" else empty end'
  done
echo "[!] If nothing printed [OK], reads of $BUCKET were NEVER recorded. Data events are off by"
echo "    default, billable and not enablable retroactively — absence is not evidence of no read."

echo
echo "=== Everything this principal did ==="
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

Read the session for what came *before* the flag change as much as after. A principal that
enumerated buckets and read policies first is behaving differently from one that lowered a flag as
step one of a deployment.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Order matters. Restoring the flag suppresses the *effect* of a public configuration but does not
remove it, so Step 1 buys time and Step 3 is the actual fix.

**Break-glass — use the break-glass credential, not the on-call's own.** If the account-level block was lowered, or `get-bucket-policy-status` returns
`True` on a bucket holding production data, run Step 1 and Step 4 in parallel and skip the
sequencing. Every minute the configuration stands is anonymous internet read access.

#### Step 1 — Restore the block, at both scopes

```bash
BUCKET="${1:?bucket name required}"
ACCT="$(aws sts get-caller-identity --query Account --output text)"
PAB="BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Account first — it is the floor, and setting it constrains every bucket at once.
aws s3control put-public-access-block --account-id "$ACCT" \
  --public-access-block-configuration "$PAB" \
  && echo "[OK] account-level block set (all four)"

# Then the bucket. All four are sent explicitly: a partial document has undocumented merge
# semantics, so restoring one flag by name risks leaving the others as the attacker left them.
if aws s3api head-bucket --bucket "$BUCKET" >/dev/null 2>&1; then
  aws s3api put-public-access-block --bucket "$BUCKET" \
    --public-access-block-configuration "$PAB" \
    && echo "[OK] bucket block restored on $BUCKET (all four)"
else
  echo "[FAIL] bucket $BUCKET not found or not accessible"
fi
```

**Before running the account call:** the floor applies to every bucket. If a legitimately public
bucket exists here — a static site, a public dataset — this takes it offline. That may still be the
right trade during an active exposure, but it is a decision rather than a side effect.

#### Step 2 — Confirm what Step 1 did and did not fix

```bash
BUCKET="${1:?bucket name required}"

aws s3api get-bucket-policy-status --bucket "$BUCKET" \
  --query 'PolicyStatus.IsPublic' --output text 2>/dev/null

if aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text 2>/dev/null \
   | grep -q '"\*"'; then
  echo "[!] policy still contains a wildcard principal — suppressed by the block, NOT removed"
  echo "    proceed to Step 3"
else
  echo "[OK] no wildcard principal in the bucket policy"
fi
```

`IsPublic` may now read `False` while the public statement sits untouched in the policy — the block
is masking it, and anyone who can set the flag back re-exposes the bucket in one call. The finding
is not closed here.

#### Step 3 — Remove the public grant itself

```bash
BUCKET="${1:?bucket name required}"
TS="$(date -u '+%Y%m%dT%H%M%SZ')"
BAK="/tmp/${BUCKET}-policy-${TS}.json"

aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text > "$BAK" 2>/dev/null \
  && echo "[OK] policy preserved at $BAK" || echo "(no policy to preserve)"

if [ -s "$BAK" ]; then
  # Preserve non-public statements: a bucket policy is often the only record of a legitimate
  # cross-account arrangement, and deleting it wholesale breaks a consumer nobody remembers.
  KEPT="$(jq -c '
    (if (.Statement | type) == "object" then [.Statement] else .Statement end) as $s
    | def pub: .Effect == "Allow" and ([(.Principal | if type == "string" then [.]
        else (to_entries[].value | if type == "array" then .[] else . end) end)]
        | flatten | index("*")) != null;
      {removed: ([$s[] | select(pub)] | length), doc: (. + {Statement: [$s[] | select(pub | not)]})}
  ' "$BAK")"
  N="$(printf '%s' "$KEPT" | jq -r '.removed')"
  R="$(printf '%s' "$KEPT" | jq -r '.doc.Statement | length')"
  if [ "$N" = "0" ]; then
    echo "[OK] no public Allow statement to remove"
  elif [ "$R" = "0" ]; then
    aws s3api delete-bucket-policy --bucket "$BUCKET" \
      && echo "[OK] policy was entirely public — deleted (backup at $BAK)"
  else
    printf '%s' "$KEPT" | jq -c '.doc' \
      | xargs -0 -I{} aws s3api put-bucket-policy --bucket "$BUCKET" --policy {} \
      && echo "[OK] removed $N public statement(s), kept $R"
  fi
fi

# ACL grants are separate from the policy and survive every step above.
aws s3api put-bucket-acl --bucket "$BUCKET" --acl private && echo "[OK] bucket ACL reset to private"
```

#### Step 4 — Contain the principal

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

---

## 4. Eradication

### Remove Attacker Access

#### Treat the exposure window as full disclosure

The window runs from the first flag change to the moment Step 3 completed. Within it anyone on the
internet could read every object the public grant covered, and unless data events were already
enabled there is **no record of whether they did**. Query 4 establishes which case you are in.

When data events were off, the honest position is: assume every object in scope was retrieved. The
alternative is reporting "no evidence of access" when no evidence could have existed, which is
materially misleading in front of a legal or compliance decision. Inventory what the bucket held
during the window — including objects since deleted — and route it down the §1 disclosure path.

#### Close every other bucket the sweep found

Query 2 rarely finds only one. Work the `IMMEDIATE-EFFECT` rows first — those are exposures. The
`prospective` rows are open doors and can follow.

#### Set the account floor and keep it set

With all four flags true at the account, a compromised principal can set a bucket flag false all day
and change nothing. Combine it with an SCP so the floor cannot be lowered:

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

#### Right-size who can change bucket access configuration

`s3:PutBucketPublicAccessBlock`, `s3:PutBucketPolicy`, `s3:PutBucketAcl` and their account-scope
equivalents belong to infrastructure automation. Review every identity and resource policy granting
them, and every wildcard (`s3:Put*`, `s3:*`) that grants them by accident — the wildcard is usually
how the permission arrived.

---

## 5. Recovery

### Restore Clean State

#### Verify the floor is set and no bucket is public

Re-run **§2 Query 2**: recovery is verified when it reports the account floor set and no bucket
carrying an `IMMEDIATE-EFFECT` flag. Then assert the effective verdict, which the sweep does not
cover:

```bash
aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n' \
| while read -r B; do
    [ -z "$B" ] && continue
    P="$(aws s3api get-bucket-policy-status --bucket "$B" \
           --query 'PolicyStatus.IsPublic' --output text 2>/dev/null)"
    case "$P" in
      True)     echo "[FAIL] $B — still public" ;;
      False|"") echo "[OK] $B" ;;
      *)        echo "[!] $B — could not determine ($P)" ;;
    esac
  done
```

A bucket reporting `[OK]` only because the restored block is masking a public statement is not
recovered. Step 3 is what removes the statement, which is why it runs before this check rather than
instead of it.

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

The internal check confirms the configuration; this confirms the outcome. They can disagree — a
CloudFront distribution or an S3 Access Point can keep content reachable after the bucket itself is
locked down — and the outside view is the one that answers a disclosure question.

#### Confirm the corrected detection fires

```bash
BUCKET="${1:?disposable test bucket required — do NOT use a production bucket}"

# A PROSPECTIVE flag is exercised deliberately: it proves the rule fires and the routing works with
# no possibility of exposing an object, and it validates the medium/high split — the alert that
# arrives should be the medium one.
aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=true \
  && echo "[OK] BlockPublicPolicy set false — expect the medium rule within 15 min"

sleep 60
aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
  && echo "[OK] restored"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Which flag was lowered, and did the alert say? | The whole response splits on immediate-effect versus prospective. If the alert did not distinguish them, the responder lost time establishing it. |
| Was the account-level block set at the time? | If it was, the bucket change was inert and this is misconfiguration, not exposure. If it was not, the missing floor is the finding. |
| How did the principal hold `s3:PutBucketPublicAccessBlock`? | Usually via an `s3:*` or `s3:Put*` wildcard that nobody intended to include it. |
| Were object data events enabled for this bucket? | Determines whether "what was taken" is answerable at all — and that was decided months ago, not during the incident. |
| Did a policy or ACL write follow the flag change? | The pair is the incident; the flag alone is the precondition. |
| How long did the window stand? | Directly sizes the disclosure question. |

### Recommended Guardrails

**The account-level block is the control that matters.** Everything else here is secondary to it.
With all four flags true at the account, a bucket-level weakening changes nothing and these alerts
become early warning rather than incident notification.

**Deny the account-scope operations by SCP**, with a named break-glass exception, using the fragment
in §4. Bucket-scope operations are harder to deny outright because legitimately public buckets
exist; account scope almost never has a good reason to move.

**Alert on the flag, not on the outcome.** By the time an object is read the exposure has happened.
The prospective flags are the earliest signal available, which is why they ship at medium rather
than being dropped as low-value.

**Keep the public-bucket inventory as data.** Every alert here needs the answer to "is this bucket
supposed to be public", and a list a query can join against turns a fifteen-minute conversation into
a column. Pair it with object data events on buckets holding regulated data — the only way the
disclosure question stays answerable, and it cannot be decided retroactively.

### Technique Reference

**T1530 — Data from Cloud Storage.** Verified live at https://attack.mitre.org/techniques/T1530/ on
2026-08-30.

The source rule carried **no** MITRE mapping. T1530 is the correct one: the objective is reading
data out of cloud storage and lowering Block Public Access is the enabling step. Where the exposure
is used to move data to attacker-controlled infrastructure, T1567.002 applies to that later stage
and is not covered here.

AWS references relied on throughout, all verified 2026-08-30:

- `PutPublicAccessBlock` API reference — per-flag semantics and the `Required: No` status of all
  four flags: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html
- S3 CloudTrail event names, including the API-versus-event divergence:
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html
- Block Public Access scope interaction — "the most restrictive combination":
  https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html

Service-wide verified behaviour shared by every `s3.*` playbook is in `../_ground-truth/s3.md`.

### Residual Risk

**A bucket that is public by design stays a gap.** These rules cannot distinguish a deliberate
public bucket from a compromised one without the §1 inventory, and where that inventory is stale the
rule will either alert forever or be tuned into silence.

**Access points and CloudFront route around the bucket.** A bucket locked down at the bucket level
can still serve content through an S3 Access Point with its own policy, or a CloudFront distribution
with an origin access identity. The outside-in check in §5 catches this; the CloudTrail rules do not.

**Object reads remain invisible where data events are off.** The largest residual gap, and a cost
decision rather than a detection one. The playbook is explicit about it so that "no evidence of
access" is never reported when no evidence was possible.

**Cross-account ACL grantee detail is redacted from the owner's trail.** Where exposure was granted
by ACL to a specific external account, the owner's CloudTrail record does not carry who. The live
ACL read in Query 3 is the only source, and only until it changes.
