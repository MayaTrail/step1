# IR Playbook: KMS Key Policy Access Removed — `PutKeyPolicy`, the one path with no window

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Impact — a key policy is replaced so that principals lose the ability to decrypt, leaving the data intact and unreadable |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical when the lockout safety check was bypassed or the account-root statement dropped across several keys; high for a single policy without the root statement, or a sweep outside provisioning; medium for a routine replacement. The source rule is P3 and fires on almost every `PutKeyPolicy`. |
| MITRE Tactics | Impact |
| MITRE Techniques | T1486 |
| Services in Scope | KMS, IAM, CloudTrail |

**What the technique does:** the actor replaces a key policy so that the principals who need to
decrypt no longer can. The data is untouched — every byte of ciphertext is identical before and
after — and it is unreadable.

This is the one route of the four with no window:

| Call | Reversal |
|---|---|
| `DisableKey` | Instant, with `EnableKey` |
| `ScheduleKeyDeletion` | `CancelKeyDeletion`, within 7–30 days |
| `DeleteImportedKeyMaterial` | Re-import the same material — if you hold it |
| **`PutKeyPolicy`** | **Only if the new policy still lets you call `PutKeyPolicy`** |

**Why the usual reflexes miss it.** The first is the source rule's inverted negation, which makes it
fire on nearly every policy change. The second is its `policyName` filter, which excludes nothing and
silently drops callers who omitted the parameter — the two defects cancel enough that the alert
volume looks reasonable. The third is expecting a "principal removed" event: `PutKeyPolicy` replaces
the document, so removal is an absence. The fourth is assuming IAM can fix it, when AWS states
plainly that IAM cannot grant access a key policy has not allowed.

**Detection thesis:** read the submitted policy document, test it for the account-root statement, and
correct the negation so the lockout bypass is the critical signal it deserves to be.

**Adjacent playbooks.** `DisableKey` is `../kms.impact.kms-key-disabled/`. `ScheduleKeyDeletion` is
`../kms.impact.kms-key-scheduled-deletion/` and `../kms.impact.multiple-kms-keys-scheduled-deletion/`.
Key creation, external key material and the cross-account ransomware pattern are
`../kms.impact.key-created/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. `PutKeyPolicy` is control-plane and logged by default,
and the **full submitted policy document** is in `requestParameters` — which is the only record of
what the policy became, since KMS keeps no version history.

**A stored copy of every customer key policy**, refreshed on a schedule. `PutKeyPolicy` replaces
rather than merges, so the only way to know what was removed is to have kept what was there. This is
the single most valuable preparation step in this playbook.

**A break-glass principal named in every key policy.** IAM rights are not sufficient; the key policy
must allow it. A key whose policy omits your break-glass role is unmanageable by you no matter what
IAM says.

**Alerting (must be pre-configured)**

- **`PutKeyPolicy` with `BypassPolicyLockoutSafetyCheck: true` → P0**
- **`PutKeyPolicy` submitting a policy with no account-root statement → P1**
- **Three or more keys re-policied by one principal in thirty minutes → P1**

**Response Tooling**

An IAM principal that can call `kms get-key-policy` and `kms put-key-policy`, **and that is named in
the key policies themselves**. This is the one playbook where the response tooling can be locked out
by the incident, and confirming it beforehand is the difference between a five-minute fix and an AWS
Support case.

**Known IOC Baselines**

The provisioning roles that write key policies. Compliance tooling that standardises policies across
keys is the dominant false positive for the sweep correlation.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `PutKeyPolicy` with `BypassPolicyLockoutSafetyCheck: true` | CloudTrail | T1486 |
| P1 | `PutKeyPolicy` submitting a policy containing no account-root principal | CloudTrail | T1486 |
| P1 | Three or more keys re-policied by one principal within thirty minutes | Correlation rule | T1486 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | A submitted policy naming a principal outside this account | CloudTrail | T1486 |
| P2 | `PutKeyPolicy` outside the provisioning path | CloudTrail | T1486 |
| P3 | A submitted policy noticeably shorter than the one it replaced | CloudTrail + stored baseline | T1486 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `NOT bypassPolicyLockoutSafetyCheck:"false"` | The parameter is **absent** on an ordinary call, not present-and-false. `NOT field:"false"` is true for every ordinary call, so the rule fires on all of them | Match the value `true` being present |
| `policyName:"default"` | AWS permits exactly one value, so it excludes nothing — but it requires the field to be present, silently dropping callers who omitted it | Clause removed entirely |
| The two defects partly cancel | One makes it fire on everything, the other narrows it back. The volume looks plausible while the rule detects neither what it claims nor a stable subset | Both corrected, and the intended signal isolated |
| No test on the submitted policy | `PutKeyPolicy` replaces rather than merges, so removal is an absence. The document is right there in `requestParameters` | A rule testing the document for the account-root statement |
| `T1565 — Data Manipulation` | Removing key access alters no data; the ciphertext is byte-identical. What changes is whether anyone can read it | `T1486 — Data Encrypted for Impact` |
| Threshold of zero, no volume dimension | One deliberate change and a sweep across every key in the account look the same | A three-keys-in-thirty-minutes correlation |

**Recommended detection — the negation corrected and the policy document read.**

```yaml
# KMS key policy access removed (T1486)
#
# THE SOURCE RULE'S NEGATION IS INVERTED. It ends `NOT bypassPolicyLockoutSafetyCheck:"false"`. The
# parameter is OPTIONAL, so on an ordinary PutKeyPolicy it is ABSENT — not present-and-false. `NOT
# field:"false"` is therefore true for every ordinary call and the rule fires on all of them. It
# meant `= true`, which is what the first document below matches.
#
# AND ITS `policyName:"default"` CLAUSE IS A NO-OP THAT ALSO DROPS EVENTS. AWS: the only valid value
# is `default`. It can never exclude a policy by name, but it does require the field to be PRESENT,
# so callers who omit the optional parameter are silently dropped. The two defects push in opposite
# directions, which is why the alert volume looked plausible. See ../../_ground-truth/kms.md §3, §4.
#
# THE LARGER CASE THE RULE NEVER REACHES: a policy that omits the account-root statement.
# PutKeyPolicy REPLACES the policy rather than merging it, so a principal is removed by being left
# out — no distinct event, no diff, only the new document. And "without permission from the key
# policy, IAM policies that allow permissions have no effect", so removing that statement cuts off
# every IAM-delegated principal at once and no IAM change restores it. See §5.
#
# MITRE: the source maps Data Manipulation. Removing key access alters no data — the ciphertext is
# byte-identical. What changes is whether anyone can read it.
title: KMS key policy written with the lockout safety check bypassed
id: 528050e6-51c2-4597-adac-50ede6bdd008
status: experimental
description: >-
  PutKeyPolicy with BypassPolicyLockoutSafetyCheck true. AWS documents this as being for the case
  where you intend to prevent the calling principal from making a subsequent PutKeyPolicy request —
  in other words, deliberately making the key unmanageable.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html
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
  #
  # This matches the VALUE `true` being present. It does not test for the absence of `false`, which
  # is the source rule's defect: the parameter is simply missing on an ordinary call.
  selection:
    eventSource: kms.amazonaws.com
    eventName: PutKeyPolicy
    requestParameters.bypassPolicyLockoutSafetyCheck: true
  # justified: no threshold and no allowlist. AWS documents exactly one intent for this parameter and
  # it is to lock the caller out of the key. There is no volume at which that is more interesting and
  # no automation that legitimately does it.
  condition: selection
falsepositives:
  - A key being handed to a single service principal during a migration, which should be confirmed
    against a change record rather than filtered out
level: critical
---
# The case the source rule cannot express. The account-root statement is what allows IAM to delegate
# access to the key at all; a submitted policy without it removes every IAM-delegated principal.
title: KMS key policy written without the account-root statement
id: 745f08e2-5a2e-4eb9-87ad-fb3646cd9295
status: experimental
description: >-
  PutKeyPolicy submitted a policy document that does not contain an account-root principal. Because
  IAM policies cannot grant access to a KMS key without the key policy allowing it, this removes
  IAM-delegated access for the whole account in one call and no IAM change restores it.
references:
  - https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html
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
    eventName: PutKeyPolicy
    errorCode: null
  # The root statement is written as arn:aws:iam::<account-id>:root. Matching on the ':root"' suffix
  # avoids hard-coding an account id and still catches any account's root principal.
  filter_has_root:
    requestParameters.policy|contains: ':root'
  condition: selection and not filter_has_root
falsepositives:
  - A key deliberately scoped to service principals only — a small, enumerable set that should be
    listed by key id at deployment rather than by removing this document
level: high
---
name: kms_key_policy_changed
title: KMS key policy replaced
id: e73f6f38-3d56-4066-a1fa-468bedb26057
status: experimental
description: >-
  PutKeyPolicy succeeded outside the provisioning allowlist. Informational alone. Note that
  PutKeyPolicy REPLACES the policy rather than merging it, so the event carries the new document and
  never says what was removed.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html
  - https://attack.mitre.org/techniques/T1486/
tags:
  - attack.impact
  - attack.t1486
logsource:
  product: aws
  service: cloudtrail
detection:
  # No policyName clause. AWS permits exactly one value, so filtering on it excludes nothing and
  # silently drops every caller who omitted the optional parameter.
  selection:
    eventSource: kms.amazonaws.com
    eventName: PutKeyPolicy
    errorCode: null
  filter_provisioning:
    userIdentity.arn|contains:
      - 'PlatformAutomation'
      - 'iac-deploy'
  condition: selection and not filter_provisioning
falsepositives:
  - Infrastructure provisioning that runs under a role not yet in the allowlist
level: informational
---
# Three keys re-policied by one principal in thirty minutes is a sweep. The source rule has a
# threshold of zero and so cannot distinguish one deliberate change from a walk across the account.
title: KMS key policies replaced across multiple keys by one principal
id: 371702b0-35ff-4cc3-b099-ca12c187a6c8
status: experimental
description: >-
  One principal replaced the key policy on three or more KMS keys within thirty minutes. A single
  policy change is routine; a sweep across keys is access being removed at scale, and every key
  policy is Regional so the sweep may be one of several.
references:
  - https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html
  - https://attack.mitre.org/techniques/T1486/
tags:
  - attack.impact
  - attack.t1486
correlation:
  type: value_count
  rules:
    - kms_key_policy_changed
  group-by:
    - userIdentity.arn
  timespan: 30m
  condition:
    gte: 3
    field: requestParameters.keyId
falsepositives:
  - A compliance remediation applying a standard policy across every key, which should be identifiable
    from a change record naming the same key ids
level: high
```

What this set structurally cannot do: tell you what the policy said before. KMS keeps no version
history, so the previous document has to come from a stored baseline or from an earlier
`PutKeyPolicy` event in the trail — §2 Query 2 tries both.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> **Key policies are Regional**, unlike IAM policies, so run this in every region a key exists in.
> `PutKeyPolicy` is control-plane and logged by default.

Run Query 1 first; it establishes whether anyone can still manage the key.

#### Query 1 — Reconstruct: what policy was submitted, and does it lock you out

```bash
REGION="${AWS_REGION:-us-east-1}"
ACCT="$(aws sts get-caller-identity --query Account --output text 2>/dev/null)"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutKeyPolicy \
  --start-time "$START" --region "$REGION" --output json 2>/dev/null \
| jq -r --arg acct "$ACCT" '.Events[].CloudTrailEvent | fromjson
    | select(.errorCode == null)
    | .requestParameters as $r
    # The policy is RAW JSON on the REQUEST side. The percent-encoded convention applies to response
    # elements, not here, so it is read directly.
    | ($r.policy // "") as $pol
    | [ (if $r.bypassPolicyLockoutSafetyCheck == true then "LOCKOUT-BYPASSED" else empty end),
        (if ($pol | test(":root")) then empty else "NO-ACCOUNT-ROOT" end),
        (if ($pol | test("arn:aws:iam::")) and (($pol | test("arn:aws:iam::" + $acct)) | not)
         then "EXTERNAL-PRINCIPAL" else empty end),
        (if ($pol | length) < 400 then "SHORT-POLICY" else empty end) ] as $flags
    | "\(.eventTime)  key=\($r.keyId // "-")  bytes=\($pol | length)  " +
      "[\($flags | join(","))]  by=\(.userIdentity.arn)"' | sort
```

`NO-ACCOUNT-ROOT` means IAM-delegated access is gone for the whole account on that key, and no IAM
change brings it back. `LOCKOUT-BYPASSED` means the caller deliberately wrote a policy that could
leave the key unmanageable.

#### Query 2 — Recover the previous policy document

```bash
REGION="${AWS_REGION:-us-east-1}"
KEY="${1:?key id from Query 1}"
START="$(date -u -v-90d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '90 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

echo "=== policy now ==="
aws kms get-key-policy --key-id "$KEY" --policy-name default --region "$REGION" \
  --query Policy --output text 2>/dev/null | jq . 2>/dev/null || echo "  (cannot read — you may already be locked out)"

echo
echo "=== every PutKeyPolicy ever recorded for this key, oldest first ==="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutKeyPolicy \
  --start-time "$START" --region "$REGION" --output json 2>/dev/null \
| jq -r --arg k "$KEY" '[.Events[].CloudTrailEvent | fromjson
    | select((.requestParameters.keyId // "") | contains($k))]
  | sort_by(.eventTime) | .[]
  | "--- \(.eventTime)  by \(.userIdentity.arn)", (.requestParameters.policy // "(no policy recorded)")'

echo
echo "[!] KMS keeps NO version history of key policies. The event before the incident is the only"
echo "    copy of the previous document, and it is only there if the trail reaches back far enough."
```

#### Query 3 — Establish who can still manage the key

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
    if [ -z "$POL" ]; then
      echo "[FAIL] $K — cannot read the policy; you have already lost access to this key"
    elif printf '%s' "$POL" | grep -q ':root"'; then
      echo "[OK] $K — account-root statement present, IAM delegation works"
    elif printf '%s' "$POL" | grep -q "$BREAKGLASS"; then
      echo "[!] $K — no root statement, but $BREAKGLASS is named directly"
    else
      echo "[FAIL] $K — no root statement and no $BREAKGLASS; only AWS Support can recover this"
    fi
  done
```

Run this **before** touching anything. If the break-glass principal is already excluded from a key,
every subsequent step in §3 will fail on that key and the response is an AWS Support case rather than
an API call.

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

`RevokeGrant`, `DisableKey` or `ScheduleKeyDeletion` in the same window is the same intent by other
means, and each has its own playbook. `PutKeyPolicy` across several regions is the same sweep
repeated — key policies are Regional, so one region's clean result proves nothing about the others.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore the policy first, and check you still can before doing anything else. This is the one
incident in the KMS set where the response tooling can be locked out by the incident itself.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 3 reports `[FAIL]
only AWS Support can recover this`, stop and open a support case immediately; nothing in the rest of
this section will work on that key, and the case takes time that starts running now.

#### Step 1 — Restore the previous policy

```bash
REGION="${AWS_REGION:-us-east-1}"
KEY="${1:?key id}"
POLICY_FILE="${2:?path to the previous policy document, from Query 2 or your stored baseline}"

[ -f "$POLICY_FILE" ] || { echo "[FAIL] $POLICY_FILE not found"; exit 1; }
jq . "$POLICY_FILE" >/dev/null 2>&1 || { echo "[FAIL] $POLICY_FILE is not valid JSON"; exit 1; }

grep -q ':root"' "$POLICY_FILE" \
  && echo "[OK] the document contains an account-root statement" \
  || echo "[!] the document has NO account-root statement — restoring it will not restore IAM delegation"

aws kms get-key-policy --key-id "$KEY" --policy-name default --region "$REGION" \
  --query Policy --output text 2>/dev/null > "./evidence-keypolicy-${KEY}.json" \
  && echo "[OK] current policy preserved at ./evidence-keypolicy-${KEY}.json"

read -r -p "Apply $POLICY_FILE to $KEY? [y/N] " ANS
[ "$ANS" = "y" ] && aws kms put-key-policy --key-id "$KEY" --policy-name default \
  --policy "file://$POLICY_FILE" --region "$REGION" >/dev/null 2>&1 \
  && echo "[OK] policy restored" \
  || echo "[!] not applied"
```

Deliberately **not** passing `--bypass-policy-lockout-safety-check`. The check is what stops you
restoring a document that would lock you out a second time, and it is doing its job.

#### Step 2 — Contain the principal

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

An IAM deny **does** work here even when an IAM allow would not: AWS is explicit that "you can use an
IAM policy to deny a permission to a KMS key without permission from a key policy". Denial is the one
direction IAM controls unilaterally.

#### Step 3 — Check every region

```bash
KEY_ALIAS="${1:?key alias or a description substring to search for}"

for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null); do
  HITS="$(aws kms list-aliases --region "$R" --query "Aliases[?contains(AliasName, '$KEY_ALIAS')].TargetKeyId" \
           --output text 2>/dev/null)"
  [ -z "$HITS" ] && continue
  for K in $HITS; do
    POL="$(aws kms get-key-policy --key-id "$K" --policy-name default --region "$R" \
            --query Policy --output text 2>/dev/null)"
    printf '%s' "$POL" | grep -q ':root"' \
      && echo "[OK] $R  $K" \
      || echo "[FAIL] $R  $K — no account-root statement"
  done
done
```

Key policies are Regional. A multi-Region key's replicas each carry their own, so a clean primary
proves nothing about the replicas.

#### Step 4 — Confirm what is actually unreadable

A key whose policy excludes a service does not announce itself; the applications simply start failing
to decrypt. Check the consumers of that key — S3 buckets with it as default encryption, EBS volumes,
RDS instances, Secrets Manager secrets — and confirm each can still read. `kms list-grants` is the
fastest partial answer, because a service using the key usually holds a grant on it.

---

## 4. Eradication

### Remove Attacker Access

#### Put the break-glass principal in every key policy

IAM rights alone cannot manage a KMS key. A policy that names only the account root and one team's
role is one deletion away from unmanageable, which is precisely what
`BypassPolicyLockoutSafetyCheck` exists to allow. Naming a durable break-glass role in every key
policy is the control that keeps this incident an API call instead of a support case.

#### Deny key-policy changes outside the provisioning path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyKeyPolicyChangesOutsideProvisioning",
  "Effect": "Deny",
  "Action": ["kms:PutKeyPolicy"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourProvisioningRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone, and on this action that means nobody can ever repair a key policy. Test in a non-production
OU first. This is also the one denial in the KMS set that an IAM policy could not achieve on its own,
because SCPs apply above the key policy.

#### Back up key policies on a schedule

KMS keeps no version history. A daily `get-key-policy` across every customer key, committed
somewhere, converts this incident from forensic reconstruction into a restore. It is the highest-value
control in this playbook and it is three lines of script.

#### Never bypass the lockout check in your own automation

If a pipeline passes `--bypass-policy-lockout-safety-check` as a matter of habit, the guardrail is
gone before an attacker arrives — and the corrected detection will report the pipeline as critical,
correctly.

---

## 5. Recovery

### Restore Clean State

#### Verify every customer key is manageable

```bash
REGION="${AWS_REGION:-us-east-1}"

aws kms list-keys --region "$REGION" --query 'Keys[].KeyId' --output text 2>/dev/null \
| tr '\t' '\n' | while read -r K; do
    [ -z "$K" ] && continue
    MGR="$(aws kms describe-key --key-id "$K" --region "$REGION" \
            --query 'KeyMetadata.KeyManager' --output text 2>/dev/null)"
    [ "$MGR" = "CUSTOMER" ] || continue
    POL="$(aws kms get-key-policy --key-id "$K" --policy-name default --region "$REGION" \
            --query Policy --output text 2>/dev/null)"
    printf '%s' "$POL" | grep -q ':root"' \
      && echo "[OK] $K" \
      || echo "[FAIL] $K — no account-root statement; IAM delegation does not work on this key"
  done
```

#### Verify the consumers can decrypt again

```bash
REGION="${AWS_REGION:-us-east-1}"
KEY="${1:?key id}"

aws kms list-grants --key-id "$KEY" --region "$REGION" --output json 2>/dev/null \
| jq -r '.Grants[] | "  grant \(.GrantId)  grantee=\(.GranteePrincipal)  ops=\((.Operations // []) | join(","))"'

echo "[!] A grant surviving does not prove decryption works — the key policy is evaluated too."
echo "    Confirm from the consumer side: read one object from the bucket, or one value from the"
echo "    secret, that this key protects. That is the only end-to-end test."
```

#### Confirm the corrected detection fires

```bash
REGION="${AWS_REGION:-us-east-1}"
KEY="${1:?a NON-PRODUCTION key id}"

# Re-apply the key's CURRENT policy unchanged. Nothing changes, but a PutKeyPolicy event is produced
# with a full document containing the account-root statement — which must NOT raise the high alert.
aws kms get-key-policy --key-id "$KEY" --policy-name default --region "$REGION" \
  --query Policy --output text 2>/dev/null > /tmp/keypolicy-$$.json

if grep -q ':root"' /tmp/keypolicy-$$.json; then
  aws kms put-key-policy --key-id "$KEY" --policy-name default \
    --policy "file:///tmp/keypolicy-$$.json" --region "$REGION" >/dev/null 2>&1 \
    && echo "[OK] policy re-applied unchanged — expect at most the informational base rule"
  echo "[!] If this raises a HIGH or CRITICAL alert, the source rule's inverted negation is still"
  echo "    deployed: it fires on every ordinary PutKeyPolicy."
else
  echo "[!] $KEY has no account-root statement — fix that before using it as a test key"
fi
rm -f /tmp/keypolicy-$$.json
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Did the submitted policy contain an account-root statement? | Without it, IAM-delegated access is gone for the whole account and no IAM change restores it. |
| Was the lockout safety check bypassed? | AWS documents one intent for it: preventing the caller from changing the policy again. |
| Can the break-glass principal still read the policy? | It decides whether this is an API call or an AWS Support case, and it should be checked first. |
| Was a previous copy of the policy available? | KMS keeps no version history, so recovery depends entirely on a stored baseline or an older CloudTrail event. |
| Were other regions affected? | Key policies are Regional and a multi-Region key's replicas each carry their own. |
| Which consumers stopped being able to decrypt? | The failure surfaces as application errors, not as a KMS event. |

### Recommended Guardrails

**Test the value, never the absence of `"false"`.** An optional parameter is missing, not false, and
that single mistake made this rule fire on nearly every policy change.

**Drop the `policyName` clause.** One valid value means it filters nothing and drops every caller who
omitted it.

**Back up key policies daily.** KMS keeps no history; the backup is what turns this into a restore.

**Name a durable break-glass principal in every key policy.** IAM cannot grant what the key policy
has not allowed.

**Alert on the submitted document, not the call.** Removal is an absence, and the absence is visible
only by reading the policy in the event.

### Technique Reference

**T1486 — Data Encrypted for Impact.** Verified live at https://attack.mitre.org/techniques/T1486/ on
2026-08-30. The data is already encrypted; removing key access is what makes it unreadable, and the
impact is identical to encrypting it afresh.

The source rule maps `T1565 — Data Manipulation`. No data is manipulated — the ciphertext is
byte-identical before and after. `T1531 — Account Access Removal` (verified live 2026-08-30) was
considered and set aside: it concerns access to accounts, not to resource keys.

AWS references relied on throughout, all verified 2026-08-30:

- `PutKeyPolicy` API reference — `BypassPolicyLockoutSafetyCheck` semantics and the statement that the
  only valid `PolicyName` is `default`:
  https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html
- Key policies — "without permission from the key policy, IAM policies that allow permissions have no
  effect", and that key policies are Regional:
  https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html

Service-wide verified behaviour shared by the `kms.*` playbooks authored against it is in
`../_ground-truth/kms.md`.

### Residual Risk

**Recovery may not be available to you at all.** If the new policy excludes every principal you
control, no API call fixes it and AWS Support is the only route.

**KMS keeps no policy history.** Without a stored baseline, the previous document exists only in an
older CloudTrail event, and only if retention reaches back that far.

**A grant can survive while decryption still fails.** Grants and the key policy are evaluated
together, so a surviving grant is not proof of access — only a read from the consumer side is.

**The failure is silent on the KMS side.** Nothing reports that a service lost access; it surfaces as
decryption errors in applications, which may be attributed to the application for hours.
