# IR Playbook: KMS Key Created — `CreateKey` with external key material

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Impact — a key is created whose material, policy or manageability puts data at risk of being made unreadable |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical when imported key material is deleted; high for an external-origin key, a bypassed lockout check, or a creation-time policy naming another account; medium for volume outside the provisioning path. A plain key creation is informational. Both source rules are P3/P4 and neither can fire. |
| MITRE Tactics | Impact |
| MITRE Techniques | T1486 |
| Services in Scope | KMS, CloudTrail, S3, EBS |

**What the technique does:** the actor creates a key they control and puts data under it. Creation
itself encrypts nothing — the severity is entirely in four request parameters:

| Parameter | Why it matters |
|---|---|
| `Origin: EXTERNAL` | AWS holds no material for the key; the creator supplies and keeps it |
| `Policy` | A creation-time policy naming another account is cross-account staging |
| `BypassPolicyLockoutSafetyCheck: true` | The key is unmanageable from birth |
| `MultiRegion: true` | Replicable, so later changes are not confined to one region |

**`Origin: EXTERNAL` is the sharp one.** `DeleteImportedKeyMaterial` renders every ciphertext under
such a key unreadable **immediately** — no waiting period at all, unlike `ScheduleKeyDeletion`'s 7 to
30 days — and AWS's recovery instruction is to re-import the same material, which only the importer
holds.

**Why the usual reflexes miss it.** The first is the event name: both source rules are lowercase and
cannot fire. The second is treating creation as the impact, when it is the staging. The third is
reading five-in-ten-minutes as a human when it is a deployment. The fourth is looking in the wrong
account entirely — the canonical AWS ransomware pattern uses a key the victim does not own.

**Detection thesis:** rate on the request body, treat external origin as one call from unrecoverable,
and say plainly that the cross-account variant is detected on the data side rather than here.

**Adjacent playbooks.** `DisableKey` is `../kms.impact.kms-key-disabled/`. `ScheduleKeyDeletion` is
`../kms.impact.kms-key-scheduled-deletion/` and `../kms.impact.multiple-kms-keys-scheduled-deletion/`.
Key-policy access removal is `../kms.impact.key-policy-access-removed/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. `CreateKey` is control-plane and logged by default, so
this playbook needs nothing purchased.

**An inventory of which keys have `Origin: EXTERNAL`.** There should be very few and they should be
deliberate. This is the single most useful pre-incident artifact here, because the response to a
material deletion depends entirely on whether anyone else holds the material.

**A recorded account id for every KMS key ARN referenced by S3 buckets and EBS volumes.** The
cross-account ransomware pattern is only visible as a key ARN whose account is not yours, and that
comparison is much faster against a recorded baseline.

**Alerting (must be pre-configured)**

- **`DeleteImportedKeyMaterial` on any key → P0**
- **`CreateKey` with `Origin: EXTERNAL` → P1**
- **`CreateKey` with `BypassPolicyLockoutSafetyCheck: true` → P1**
- **Five or more keys created in ten minutes outside the provisioning path → P2**

**Response Tooling**

An IAM principal that can call `kms describe-key`, `kms get-key-policy` and
`kms schedule-key-deletion` outside the change pipeline — and which is **named in the key policy of
every key you own**, because a key policy that omits it makes the key unmanageable no matter what IAM
says.

**Known IOC Baselines**

The provisioning roles that create keys, populating the allowlist. Key creation is cheap and
legitimate, so the volume rule is unusable without it.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `DeleteImportedKeyMaterial` — ciphertext unreadable immediately, no window | CloudTrail | T1486 |
| P1 | `CreateKey` with `Origin: EXTERNAL`, followed by `ImportKeyMaterial` | CloudTrail | T1486 |
| P1 | `CreateKey` with `BypassPolicyLockoutSafetyCheck: true` | CloudTrail | T1486 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `CreateKey` whose `Policy` names a principal outside this account | CloudTrail | T1486 |
| P2 | Five or more keys created in ten minutes outside the provisioning path | Correlation rule | T1486 |
| P3 | `CreateKey` with `MultiRegion: true` outside the provisioning path | CloudTrail | T1486 |

### Detection Rule Quality Notes

The source rules are one immediate rule and one threshold query over the same string, both fully
readable, so every row below is auditable against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `eventName:"createkey"` — lowercase, in **both** rules | CloudTrail emits `CreateKey`. Neither rule matches anything, so the immediate rule and its correlation are both inert | Documented casing |
| No content check on a call with four consequential parameters | An ordinary provisioning key and an external-origin key one call from unrecoverable arrive identically | Separate rules for external origin, bypassed lockout, and an external-account policy |
| `T1486` applied to creation itself | Creating a key encrypts nothing. It is the technique the key serves | Plain creation rated informational; severity on the parameters |
| Threshold of five in ten minutes with no principal dimension | An infrastructure apply reaches it; a person does not. The rule selects for the deployments it should ignore | Threshold kept, provisioning allowlist added to the base rule |
| Scoped to in-account creation | The canonical AWS ransomware pattern uses a key in the **attacker's** account and creates nothing in yours | Named explicitly in §4 as a data-side detection rather than pretended to be covered |

**What the source gets right:** the two rules share one query and differ only in threshold, which is
already a base rule plus a correlation. That structure is kept.

**Recommended detection — severity read from the request body.**

```yaml
# KMS key created (T1486)
#
# NEITHER SOURCE RULE CAN FIRE. Both match `eventName:"createkey"`; CloudTrail emits `CreateKey`, and
# on a case-sensitive field the lowercase form matches nothing. Twelfth instance of that defect class
# across the source set — see ../../_ground-truth/kms.md §7.
#
# CREATING A KEY ENCRYPTS NOTHING. Both rules map to Data Encrypted for Impact, which is what the key
# is later USED for. A new key on its own is a one-dollar-a-month resource with no data under it, so
# plain creation is informational here and the severity sits on the request parameters.
#
# AND THE REQUEST BODY IS WHERE THIS USE CASE LIVES. `Origin: EXTERNAL` produces a key whose material
# AWS never holds; DeleteImportedKeyMaterial then makes every ciphertext under it unreadable
# IMMEDIATELY, with no 7-to-30-day window and no recovery except re-importing material only the
# importer has. A `Policy` admitting an external account is cross-account staging.
# `BypassPolicyLockoutSafetyCheck: true` produces a key that is unmanageable from birth. The source
# rules read none of them. See ../../_ground-truth/kms.md §1 and §2.
#
# `CreateKey` IS CONTROL-PLANE AND LOGGED BY DEFAULT, so every document below works without any
# additional trail configuration.
title: KMS key created with externally supplied key material
id: edeb5afb-e3aa-4fd7-9486-17c9a5ca0159
status: experimental
description: >-
  CreateKey with Origin EXTERNAL produces a key holding no AWS-generated material — the creator
  imports their own, and AWS never has it. DeleteImportedKeyMaterial then renders every ciphertext
  under the key unreadable immediately, with no waiting period, recoverable only by re-importing
  material the importer holds.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteImportedKeyMaterial.html
  - https://attack.mitre.org/techniques/T1486/
tags:
  - attack.impact
  - attack.t1486
logsource:
  product: aws
  service: cloudtrail
detection:
  # All three keys are on the SAME event: CloudTrail writes eventSource, eventName and the request
  # body of one API call into one record. ANDing them is correct.
  selection:
    eventSource: kms.amazonaws.com
    eventName: CreateKey
    requestParameters.origin: EXTERNAL
  # justified: no threshold and no allowlist. Imported key material is rare and deliberate; where an
  # organisation genuinely uses it — a compliance requirement to hold material outside AWS — the
  # creating role is known and belongs in an explicit allowlist added at deployment, not in a
  # threshold that would hide the first one.
  condition: selection
falsepositives:
  - Organisations with a regulatory requirement to retain key material outside AWS, which is a small
    and enumerable set of keys
level: high
---
# A key created with the safety check bypassed is unmanageable from birth. AWS: use this "only when
# you intend to prevent the principal that is making the request from making a subsequent
# PutKeyPolicy request".
title: KMS key created with the policy lockout safety check bypassed
id: a794bf87-2c99-4a4a-a7e3-e19e548c4c28
status: experimental
description: >-
  CreateKey with BypassPolicyLockoutSafetyCheck true. The check exists to stop a key policy being
  written that leaves nobody able to manage the key; bypassing it at creation produces exactly that.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html
  - https://attack.mitre.org/techniques/T1486/
tags:
  - attack.impact
  - attack.t1486
logsource:
  product: aws
  service: cloudtrail
detection:
  # The parameter is OPTIONAL and therefore ABSENT on an ordinary call — not present-and-false. This
  # matches the value `true` being present, never the absence of `false`.
  selection:
    eventSource: kms.amazonaws.com
    eventName: CreateKey
    requestParameters.bypassPolicyLockoutSafetyCheck: true
  # justified: no threshold. One key that nobody can manage is the finding; a second does not make it
  # worse. There is no legitimate automated use, so an allowlist would only create a bypass.
  condition: selection
falsepositives:
  - A key deliberately scoped to a single service principal during a migration, which should be
    confirmed against a change record rather than filtered out
level: high
---
name: kms_key_created
title: KMS key created
id: e2621dbb-f155-4ce2-a523-1de9f3ddf5a8
status: experimental
description: >-
  CreateKey succeeded outside the provisioning allowlist. Informational on its own — a new key
  encrypts nothing and costs a dollar a month. Base rule for the correlation below; the allowlist
  lives here so that the correlation counts only what a person did.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html
  - https://attack.mitre.org/techniques/T1486/
tags:
  - attack.impact
  - attack.t1486
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: kms.amazonaws.com
    eventName: CreateKey
    errorCode: null
  filter_provisioning:
    userIdentity.arn|contains:
      - 'PlatformAutomation'
      - 'iac-deploy'
  condition: selection and not filter_provisioning
falsepositives:
  - Infrastructure provisioning that runs under a role not yet in the allowlist, which is the
    overwhelming majority of key creation and is fixed by adding the role
level: informational
---
# Five in ten minutes, with a provisioning allowlist doing the discrimination. The source threshold is
# the same but has no principal dimension, so it selects for exactly the deployments it should ignore.
title: KMS keys created in volume outside the provisioning path
id: 10364d3e-a02f-4b2b-90ca-c22ed0065606
status: experimental
description: >-
  Five or more keys created within ten minutes by a principal outside the provisioning allowlist. The
  volume signal is weak on its own — key creation is cheap and legitimate — so the allowlist carries
  the discrimination rather than the count.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html
  - https://attack.mitre.org/techniques/T1486/
tags:
  - attack.impact
  - attack.t1486
correlation:
  type: event_count
  rules:
    - kms_key_created
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gte: 5
falsepositives:
  - An infrastructure apply standing up a new environment — identify the role once and add it to the
    allowlist rather than raising the count
level: medium
```

What this set structurally cannot do: see a key in another account. Where data was re-encrypted under
an attacker-owned key, nothing is created here and the detection is on the data side — §2 Query 3.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> KMS is **regional** and multi-Region keys have per-region replicas. `CreateKey` is control-plane and
> logged by default, so these queries work without any additional trail configuration.

Run Query 1 first; it establishes which parameters were used.

#### Query 1 — Reconstruct: what kind of key, and what happened to it afterwards

```bash
REGION="${AWS_REGION:-us-east-1}"
ACCT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in CreateKey ImportKeyMaterial DeleteImportedKeyMaterial ReplicateKey; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r --arg acct "$ACCT" '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | .requestParameters as $r
      # bypassPolicyLockoutSafetyCheck and multiRegion are OPTIONAL — absent means the caller omitted
      # them, which means the default. Their ABSENCE is not the value false.
      | [ (if ($r.origin // "AWS_KMS") == "EXTERNAL" then "EXTERNAL-ORIGIN" else empty end),
          (if $r.bypassPolicyLockoutSafetyCheck == true then "LOCKOUT-BYPASSED" else empty end),
          (if $r.multiRegion == true then "multi-region" else empty end),
          # CreateKey policy is RAW JSON on the request side, not percent-encoded.
          (if (($r.policy // "") | test("arn:aws:iam::")) and (($r.policy // "") | test("arn:aws:iam::" + $acct) | not)
           then "EXTERNAL-PRINCIPAL-IN-POLICY" else empty end) ] as $flags
      | "\(.eventTime)  \(.eventName)  key=\(.responseElements.keyMetadata.keyId // $r.keyId // "-")  " +
        "[\($flags | join(","))]  by=\(.userIdentity.arn)"'
done | sort
```

A `DeleteImportedKeyMaterial` line is the P0 and there is no window on it. An `EXTERNAL-ORIGIN`
creation followed by `ImportKeyMaterial` is that same P0 waiting to happen.

#### Query 2 — Inspect the keys themselves

```bash
REGION="${AWS_REGION:-us-east-1}"

aws kms list-keys --region "$REGION" --query 'Keys[].KeyId' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r K; do
    [ -z "$K" ] && continue
    aws kms describe-key --key-id "$K" --region "$REGION" --output json 2>/dev/null \
    | jq -r '.KeyMetadata
        | select(.KeyManager == "CUSTOMER")
        | if (.Origin == "EXTERNAL") then
            "[!] \(.KeyId)  ORIGIN=EXTERNAL  state=\(.KeyState)  expires=\(.ValidTo // "no expiry")  \(.Description // "")"
          else
            "[OK] \(.KeyId)  origin=\(.Origin)  state=\(.KeyState)  \(.Description // "")"
          end'
  done

cat <<'NOTE'

[!] KeyManager CUSTOMER filters out AWS-managed keys, which are numerous and not in scope.
[!] A key in state PendingImport had its material deleted and is unusable NOW. Everything encrypted
    under it is unreadable until the same material is re-imported — which requires whoever holds it.
[!] A ValidTo date on an external-origin key means the material EXPIRES on its own. That is a
    scheduled outage nobody set an alarm for.
NOTE
```

#### Query 3 — The cross-account variant, which this playbook's rules cannot see

```bash
REGION="${AWS_REGION:-us-east-1}"
ACCT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"
echo "This account: $ACCT"
echo

echo "=== S3 buckets whose default encryption names a KMS key ==="
aws s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null | tr '\t' '\n' \
| while read -r B; do
    [ -z "$B" ] && continue
    KID="$(aws s3api get-bucket-encryption --bucket "$B" 2>/dev/null \
            | jq -r '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID // empty')"
    [ -z "$KID" ] && continue
    case "$KID" in
      *":${ACCT}:"*|alias/*) echo "[OK] $B  $KID" ;;
      *)                     echo "[FAIL] $B  $KID — key ARN is NOT in this account" ;;
    esac
  done

echo
echo "[!] This is where the canonical AWS ransomware pattern is visible: data encrypted under a key"
echo "    held in the ATTACKER's account. Nothing is created in your account, so no CreateKey rule —"
echo "    including the corrected ones here — will ever fire on it."
```

#### Query 4 — Full session reconstruction of the principal

```bash
PRINCIPAL="${1:?principal ARN from Query 1 required}"
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

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

`PutBucketEncryption`, `CopyObject` at volume, or `CreateSnapshot` around the key creation is the key
being *used* — which is the point at which staging becomes impact.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

A newly created key is not urgent. An external-origin key with material imported is, because the step
that makes data unreadable takes one call and leaves no window.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 1 shows
`DeleteImportedKeyMaterial`, data is already unreadable and the incident is a recovery problem: find
who holds the material, and identify every resource encrypted under that key before anything else.

#### Step 1 — Find what is encrypted under the key

```bash
KEY="${1:?key id or ARN from Query 1}"
REGION="${AWS_REGION:-us-east-1}"

echo "=== Aliases ==="
aws kms list-aliases --key-id "$KEY" --region "$REGION" \
  --query 'Aliases[].AliasName' --output text 2>/dev/null | sed 's/^/  /'

echo "=== Grants ==="
aws kms list-grants --key-id "$KEY" --region "$REGION" --output json 2>/dev/null \
| jq -r '.Grants[] | "  \(.GrantId)  grantee=\(.GranteePrincipal)  ops=\((.Operations // []) | join(","))"'

cat <<'NOTE'

[!] KMS does not maintain a list of what is encrypted under a key. Work the other way round:
      aws s3api get-bucket-encryption --bucket <b>          # per bucket
      aws ec2 describe-volumes --filters Name=encrypted,Values=true --query 'Volumes[].[VolumeId,KmsKeyId]'
      aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,KmsKeyId]'
    The grants list above is the fastest partial answer, because a service that uses the key usually
    holds a grant on it.
NOTE
```

#### Step 2 — Stop the key being usable for new encryption, without breaking decryption

```bash
KEY="${1:?key id}"
REGION="${AWS_REGION:-us-east-1}"

echo "[!] Do NOT disable or schedule deletion of a key that already protects data — that makes the"
echo "    data unreadable, which is the outcome you are trying to prevent. Restrict the key policy"
echo "    to Decrypt instead, so existing data stays readable and nothing new goes under it."

aws kms get-key-policy --key-id "$KEY" --policy-name default --region "$REGION" \
  --query Policy --output text 2>/dev/null > "./evidence-keypolicy-${KEY##*/}.json" \
  && echo "[OK] current key policy preserved at ./evidence-keypolicy-${KEY##*/}.json"

echo "[!] Then revoke grants that should not exist:"
aws kms list-grants --key-id "$KEY" --region "$REGION" \
  --query 'Grants[].[GrantId,GranteePrincipal]' --output text 2>/dev/null \
| sed 's/^/    aws kms revoke-grant --key-id '"$KEY"' --grant-id /'
```

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

#### Step 4 — Remove the key only if nothing is under it

```bash
KEY="${1:?key id}"
REGION="${AWS_REGION:-us-east-1}"

echo "[!] Only after Step 1 has confirmed nothing is encrypted under this key. ScheduleKeyDeletion"
echo "    has a 7-to-30-day window and CancelKeyDeletion undoes it, so use the LONGEST window:"
echo "    aws kms schedule-key-deletion --key-id $KEY --pending-window-in-days 30 --region $REGION"
echo "[!] Do not shorten the window to tidy up. It is the only thing standing between a mistaken"
echo "    scoping decision and permanently unreadable data."
```

---

## 4. Eradication

### Remove Attacker Access

#### Treat `Origin: EXTERNAL` as a privileged capability

Almost no organisation needs imported key material, and those that do need it for a small, named set
of keys under a regulatory requirement. Everywhere else it is a way to hold the material that protects
your data outside AWS, and `DeleteImportedKeyMaterial` is the switch.

#### Deny external origin and lockout bypass outside the provisioning path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyExternalOriginAndLockoutBypass",
  "Effect": "Deny",
  "Action": ["kms:CreateKey", "kms:ImportKeyMaterial", "kms:DeleteImportedKeyMaterial"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourProvisioningRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone, which here means no key can ever be created. Note that `kms:CreateKey` does not support a
condition key for `Origin`, so this denies key creation outright outside the named roles rather than
denying external origin specifically. Test in a non-production OU first.

#### Require your break-glass role in every key policy

IAM permissions are not sufficient to manage a KMS key: the **key policy** must also allow it. A key
whose policy names only the creator is unmanageable by anyone else regardless of their IAM rights,
which is what `BypassPolicyLockoutSafetyCheck` exists to allow. Auditing key policies for the
break-glass principal is the control that makes that scenario recoverable.

#### Detect the cross-account variant on the data side

Nothing in KMS shows a key you do not own. A scheduled check comparing every `KMSKeyId` on S3 buckets,
EBS volumes, RDS instances and snapshots against your own account id is the only place the canonical
ransomware pattern is visible.

---

## 5. Recovery

### Restore Clean State

#### Verify no key is in `PendingImport`

```bash
REGION="${AWS_REGION:-us-east-1}"

aws kms list-keys --region "$REGION" --query 'Keys[].KeyId' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r K; do
    [ -z "$K" ] && continue
    S="$(aws kms describe-key --key-id "$K" --region "$REGION" \
          --query 'KeyMetadata.KeyState' --output text 2>/dev/null)"
    case "$S" in
      PendingImport) echo "[FAIL] $K — material deleted; data under this key is unreadable now" ;;
      PendingDeletion) echo "[!] $K — scheduled for deletion; CancelKeyDeletion still works" ;;
      Enabled) echo "[OK] $K" ;;
      *) echo "[!] $K — state $S" ;;
    esac
  done
```

#### Verify every customer key is manageable

```bash
REGION="${AWS_REGION:-us-east-1}"
BREAKGLASS="${1:?break-glass role name}"

aws kms list-keys --region "$REGION" --query 'Keys[].KeyId' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r K; do
    [ -z "$K" ] && continue
    MGR="$(aws kms describe-key --key-id "$K" --region "$REGION" \
            --query 'KeyMetadata.KeyManager' --output text 2>/dev/null)"
    [ "$MGR" = "CUSTOMER" ] || continue
    POL="$(aws kms get-key-policy --key-id "$K" --policy-name default --region "$REGION" \
            --query Policy --output text 2>/dev/null)"
    if printf '%s' "$POL" | grep -q "$BREAKGLASS"; then
      echo "[OK] $K"
    else
      echo "[FAIL] $K — key policy does not name $BREAKGLASS; IAM rights alone will not manage it"
    fi
  done
```

#### Confirm the corrected detection fires

```bash
REGION="${AWS_REGION:-us-east-1}"

# Create an EXTERNAL-ORIGIN key. It holds no material, so it protects nothing and is safe to make —
# and it is the exact shape the source rules cannot distinguish from an ordinary key.
KID="$(aws kms create-key --origin EXTERNAL --description "detection-test-$$" --region "$REGION" \
        --query 'KeyMetadata.KeyId' --output text 2>/dev/null)"
if [ -n "$KID" ]; then
  echo "[OK] created external-origin key $KID — expect the HIGH alert, not a generic creation alert"
  echo "[!] If it produces the same alert as an ordinary key, the content check is not deployed."
  aws kms schedule-key-deletion --key-id "$KID" --pending-window-in-days 7 --region "$REGION" \
    >/dev/null 2>&1 && echo "[OK] test key scheduled for deletion in 7 days"
fi
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Was the key created with `Origin: EXTERNAL`? | It puts the material outside AWS and one call from making data unreadable with no window. |
| Was `BypassPolicyLockoutSafetyCheck` set? | The key is unmanageable from birth, and no amount of IAM permission fixes that. |
| Did the creation-time policy name another account? | It is cross-account staging, and the policy is in the request body where nothing was reading it. |
| Is anything actually encrypted under the key? | It decides whether the key can be removed or must be preserved. |
| Was the principal a provisioning role? | Key creation is cheap and legitimate; the identity is most of the triage. |
| Does any resource reference a key ARN outside this account? | It is the only place the canonical ransomware pattern is visible. |

### Recommended Guardrails

**Rate on the request body.** Creation is staging; `Origin`, `Policy` and the lockout bypass are the
incident.

**Never write `NOT bypassPolicyLockoutSafetyCheck:"false"`.** The parameter is absent when omitted, so
that form matches every ordinary call — the exact bug in the neighbouring `PutKeyPolicy` rule.

**Name the break-glass role in every key policy.** IAM rights alone cannot manage a KMS key, and a
policy that omits you is the failure mode this technique aims for.

**Audit `Origin: EXTERNAL` keys as a standing inventory.** They should be few, named, and expected.

**Check `KMSKeyId` account ids on the data side.** It is the only detection for the cross-account
ransomware pattern, and no KMS rule can substitute for it.

### Technique Reference

**T1486 — Data Encrypted for Impact.** Verified live at https://attack.mitre.org/techniques/T1486/ on
2026-08-30. It is the technique the key serves; creating the key is the staging step, which is why
plain creation is rated informational here.

AWS references relied on throughout, all verified 2026-08-30:

- `CreateKey` API reference — `Origin`, `Policy`, `BypassPolicyLockoutSafetyCheck`, `MultiRegion`, and
  the statement that symmetric key material "never leaves AWS KMS unencrypted":
  https://docs.aws.amazon.com/kms/latest/APIReference/API_CreateKey.html
- `DeleteImportedKeyMaterial` — immediate unusability, the `PendingImport` state, and recovery only by
  re-importing the same material:
  https://docs.aws.amazon.com/kms/latest/APIReference/API_DeleteImportedKeyMaterial.html

Service-wide verified behaviour shared by the `kms.*` playbooks authored against it is in
`../_ground-truth/kms.md`.

### Residual Risk

**The cross-account pattern produces no event in your account.** A key created and held elsewhere,
used to re-encrypt your data, is invisible to every rule in this playbook. Query 3 and the data-side
check in §4 are the only coverage.

**`DeleteImportedKeyMaterial` has no window.** Unlike `ScheduleKeyDeletion`'s 7 to 30 days, there is
no period in which to react — the data is unreadable when the call returns.

**External key material can expire on its own.** A `ValidTo` date makes the same outage happen on a
schedule with no attacker involved, and nothing alarms on it by default.

**KMS keeps no list of what a key protects.** Scoping the impact means walking S3, EBS, RDS and every
other service separately, and a resource nobody thought to check stays broken.
