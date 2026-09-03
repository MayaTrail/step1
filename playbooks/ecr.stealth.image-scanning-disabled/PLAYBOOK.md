# IR Playbook: ECR Image Scanning Disabled — coverage removed via `PutImageScanningConfiguration`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defence evasion — image vulnerability scanning is turned off for a repository, or switched registry-wide in a way that discards every existing finding while remaining nominally enabled |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. Critical when a push follows the change, or when the registry is switched to Basic and the finding history is discarded. The source rule is P4 and cannot fire. |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1685 |
| Services in Scope | ECR, Amazon Inspector, CloudTrail |

**What the technique does:** the actor removes scanning coverage. There are two calls and they are
not equivalent:

| Call | Scope | Effect |
|---|---|---|
| `PutImageScanningConfiguration` | one repository | `scanOnPush` off — new images arrive unscanned |
| `PutRegistryScanningConfiguration` | whole registry | switching Enhanced → Basic **discards every existing finding**, while scanning stays enabled |

The second is the consequential one and the source pack watches it nowhere.

**Why the usual reflexes miss it.** The first is the event name: the source rule is lowercase and
cannot fire. The second is testing `scanOnPush: false`, which the registry-level switch never sets —
scanning remains enabled and the console looks healthy while coverage drops from OS-plus-language
with continuous rescanning to OS-only. The third is checking configuration rather than findings;
three different states all present as "scanning is on". The fourth is re-enabling and considering it
closed — under Basic, scanning happens on push, so images that arrived during the gap are never
scanned unless someone triggers it.

**Detection thesis:** cover both APIs, treat a switch to Basic as evidence loss rather than a
configuration change, and confirm coverage from findings rather than from settings.

**Adjacent playbooks.** What the gap is usually for is
`../ecr.stealth.malicious-image-pushed/`. The ordered pair between them ships here as a correlation.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. ECR is **regional**, and the registry scanning
configuration is per region as well — a change in one region says nothing about another.

**A recorded scanning posture per registry and per repository**: which tier, and which repositories
have `scanOnPush`. The registry switch is only visible as a *difference*, and AWS keeps no previous
value.

**Retained scan findings outside ECR.** This is the prerequisite that survives the technique:
switching tiers discards findings inside AWS, and an exported history is the only thing that shows
what was known before.

**Alerting (must be pre-configured)**

- **`PutRegistryScanningConfiguration` switching the registry to Basic — every existing finding is discarded → P0**
- **Scanning disabled and an image pushed by the same principal within 1h → P0**

**Response Tooling**

An IAM principal that can call `ecr put-image-scanning-configuration`,
`put-registry-scanning-configuration`, `describe-registry`, `start-image-scan` and
`describe-image-scan-findings` outside the change pipeline.

**Known IOC Baselines**

The roles that own repository and registry configuration, populating `known_provisioners`.

The list of repositories where scanning is deliberately off — a scratch or mirror repository, for
instance. Without it every alert needs a conversation.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `PutRegistryScanningConfiguration` switching the registry to Basic — discards every established finding while scanning stays enabled | CloudTrail | T1685 |
| P0 | Scanning configuration changed and an image pushed by the same principal within 1h | Correlation rule | T1685 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `PutImageScanningConfiguration` setting `scanOnPush` false by a principal outside the provisioning path | CloudTrail | T1685 |
| P2 | `PutRegistryScanningConfiguration` by a principal outside the provisioning path, in either direction | CloudTrail | T1685 |
| P2 | An image with no scan findings in a repository where `scanOnPush` reads true — archived, or arrived during a gap | API state | T1685 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `eventName:"putimagescanningconfiguration"` — lowercase | CloudTrail emits `PutImageScanningConfiguration`. On a case-sensitive field the rule matches nothing and **cannot fire**. Second lowercase event name in this ECR set | Documented casing |
| Covers the per-repository Basic setting only | The registry-wide API sets the scanning **tier** and is watched nowhere in the pack | A dedicated rule on `PutRegistryScanningConfiguration` |
| Tests `scanOnPush: false` | The registry switch never sets that field. Scanning stays enabled, `scanOnPush` may still read true, and coverage silently drops from OS-plus-language with continuous rescanning to OS-only | The registry rule tests the call, not the flag, and the query flags a move to Basic as evidence loss |
| No pairing with a push | Disabling scanning matters because of what arrives next. Alone it is a configuration change | A `temporal_ordered` correlation over 1h, grouped by principal |
| Rated P4 | A control being removed, immediately before the thing it would have inspected | High, and critical for the pair or a switch to Basic |
| MITRE `T1578` | ECR is a registry, not compute | `T1685 — Disable or Modify Tools`; note there is no cloud-security-tool sub-technique, so the parent is the mapping |
| Excludes the same named human as every other ECR rule | A personal allowlist compiled into the detection logic for a whole service | A populated provisioner list |

**Recommended detection — both APIs, with the registry switch rated as evidence loss.**

```yaml
# ECR image vulnerability scanning disabled (T1685)
#
# THE RULE CANNOT FIRE. It matches `eventName:"putimagescanningconfiguration"`. CloudTrail emits
# `PutImageScanningConfiguration`, and on a case-sensitive field the lowercase form matches nothing.
# This is the second event name in the ECR set spelled in lowercase, alongside two identity-type
# values — see ../../_ground-truth/ecr.md §3.
#
# AND IT COVERS ONE SETTING OF ONE TIER. ECR has two scanning types:
#   BASIC    — AWS native, CVE database, OS packages only. Configured PER REPOSITORY by
#              PutImageScanningConfiguration, which is what this rule watches.
#   ENHANCED — Amazon Inspector, OS *and* language packages, with CONTINUOUS rescanning as new
#              vulnerabilities appear. Configured REGISTRY-WIDE by PutRegistryScanningConfiguration,
#              which the source pack watches nowhere.
#
# THE REGISTRY-LEVEL SWITCH IS THE ONE THAT DESTROYS EVIDENCE. AWS: "Switching between Enhanced
# scanning and Basic scanning will cause previously established scans to no longer be available."
# So moving Enhanced -> Basic discards every existing finding across the whole registry, in one call,
# while scanning remains nominally ENABLED — `scanOnPush` may still read true afterwards. A rule
# testing `scanOnPush: false` sees nothing, and a console check shows scanning on.
#
# ARCHIVING IS A THIRD PATH AND CHANGES NO SCANNING CONFIGURATION AT ALL. AWS: "Archived images
# cannot be scanned. Archived images must be restored before they can be scanned." That is stated in
# ../PLAYBOOK.md as a residual gap rather than pretended closed.
title: ECR repository scanning turned off
id: 1e7c3b04-9f28-4d61-a530-86b2ef70914c
name: ecr_repository_scanning_disabled
status: experimental
description: >-
  PutImageScanningConfiguration set scanOnPush to false on a repository. Images pushed from this
  point are not scanned on arrival, so a malicious or vulnerable image enters with no finding
  attached to it. This is the basic tier and one repository — the registry-wide switch is a
  different API and is covered by the sibling rule below.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutImageScanningConfiguration.html
  - https://attack.mitre.org/techniques/T1685/
tags:
  - attack.defense-evasion
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecr.amazonaws.com'
    eventName: 'PutImageScanningConfiguration'
  success:
    errorCode: null
  scanning_off:
    requestParameters.imageScanningConfiguration.scanOnPush: false
  # POPULATE BEFORE DEPLOYING with the roles that own repository configuration.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and scanning_off and not known_provisioners
falsepositives:
  - >-
    A repository moving to Enhanced scanning, where the basic per-repository setting becomes
    irrelevant and is sometimes turned off as part of the migration. The registry configuration is
    what confirms it, and the sibling rule below sees that call.
level: high
---
title: ECR registry scanning configuration changed
id: 8a40d951-2673-4e0b-95c8-f13e02a7bd46
name: ecr_registry_scanning_changed
status: experimental
description: >-
  PutRegistryScanningConfiguration succeeded. This sets the scanning type for the entire registry,
  and switching between Enhanced and Basic discards every previously established scan result — AWS
  states so explicitly. Scanning remains nominally enabled throughout, so a rule testing scanOnPush
  sees nothing and a console check looks healthy. The source pack watches this API nowhere.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html
  - https://attack.mitre.org/techniques/T1685/
tags:
  - attack.defense-evasion
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecr.amazonaws.com'
    eventName: 'PutRegistryScanningConfiguration'
  success:
    errorCode: null
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    A deliberate migration between scanning tiers, which is a real and reasonable change. It should
    be a recorded decision, because it silently discards the finding history for the whole registry
    and that consequence is rarely the intent.
level: high
---
title: ECR scanning disabled and an image then pushed
id: 4f16b28d-70ae-4c53-8912-d0e5a3671fb8
status: experimental
description: >-
  Scanning was turned off and an image pushed afterwards by the same principal. The ordering is the
  finding: disabling scanning before a push means the image arrives with no finding attached, and
  nothing downstream has a reason to question it. The reverse order is an ordinary configuration
  change on a repository that happened to be updated.
references:
  - https://attack.mitre.org/techniques/T1685/
  - https://attack.mitre.org/techniques/T1525/
tags:
  - attack.defense-evasion
  - attack.persistence
  - attack.t1685
  - attack.t1525
correlation:
  type: temporal_ordered
  rules:
    - ecr_scanning_config_changed
    - ecr_image_pushed_any
  group-by:
    - userIdentity.arn
  timespan: 1h
falsepositives:
  - >-
    A repository being created, configured and populated in one deployment run. Allowlist the
    pipeline role on the base rules rather than shortening the timespan.
level: critical
---
title: ECR scanning configuration changed
id: 3d820ce6-51b7-4a94-b06f-7e2418ad5c39
name: ecr_scanning_config_changed
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. Any successful change to
  scanning configuration at either the repository or the registry level.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html
tags:
  - attack.defense-evasion
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecr.amazonaws.com'
    eventName:
      - 'PutImageScanningConfiguration'
      - 'PutRegistryScanningConfiguration'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
title: Container image pushed to ECR
id: 62b17f4a-c380-49de-a715-0f9c26538be1
name: ecr_image_pushed_any
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. Any successful PutImage. The
  rated detections for pushing are in ../../ecr.stealth.malicious-image-pushed/.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutImage.html
tags:
  - attack.persistence
  - attack.t1525
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource:
      - 'ecr.amazonaws.com'
      - 'ecr-public.amazonaws.com'
    eventName: 'PutImage'
  success:
    errorCode: null
  condition: selection and success
level: informational
```

What this set structurally cannot do: see an image being archived. AWS states archived images cannot
be scanned, and archiving changes no scanning configuration at all — so it produces none of these
events. It is recorded as a residual gap.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> ECR is **regional**, and the registry scanning configuration is per region — a change in one
> region says nothing about another.

Run Query 1 first; it separates the repository setting from the registry switch, which diverge
sharply.

#### Query 1 — Reconstruct: which scope changed, and in which direction

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in PutImageScanningConfiguration PutRegistryScanningConfiguration PutImage CreateRepository; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | (.requestParameters | tostring) as $rp
      # The registry call sets the scanning TIER. Switching to BASIC discards every existing
      # finding across the registry while leaving scanning nominally ENABLED.
      | (if .eventName == "PutRegistryScanningConfiguration" then
             (if ($rp | test("BASIC")) then "REGISTRY -> BASIC (findings discarded)"
              elif ($rp | test("ENHANCED")) then "registry -> ENHANCED"
              else "registry scanning changed" end)
         elif .eventName == "PutImageScanningConfiguration" then
             (if ($rp | test("\"scanOnPush\":\\s*false")) then "REPO scanOnPush OFF"
              else "repo scanOnPush on" end)
         elif .eventName == "PutImage" then "image pushed"
         else "repository created" end) as $kind
      | "\(.eventTime)  \($kind)  repo=\(.requestParameters.repositoryName // "-")  by=\(.userIdentity.arn)"'
done | sort
```

A `REGISTRY -> BASIC` line is the most serious output here and it is the one no `scanOnPush` test
would produce. An `image pushed` line after any scanning change, from the same principal, is the
pair.

#### Query 2 — What is the scanning posture right now

```bash
REGION="${AWS_REGION:-us-east-1}"

echo "=== Registry scanning tier (this region) ==="
aws ecr describe-registry --region "$REGION" --output json 2>/dev/null \
| jq -r '"  replication rules: \((.replicationConfiguration.rules // []) | length)"'
aws ecr get-registry-scanning-configuration --region "$REGION" --output json 2>/dev/null \
| jq -r '"  scanType: \(.scanningConfiguration.scanType // "unknown")",
         ((.scanningConfiguration.rules // [])[] | "  rule: \(.scanFrequency) on \([.repositoryFilters[].filter] | join(", "))")' \
  || echo "  [!] could not read the registry scanning configuration"

echo
echo "=== Per-repository scanOnPush ==="
aws ecr describe-repositories --region "$REGION" --output json 2>/dev/null \
| jq -r '.repositories[]
    | (if (.imageScanningConfiguration.scanOnPush // false) then "[OK] " else "[!]  " end)
      + "\(.repositoryName)  scanOnPush=\(.imageScanningConfiguration.scanOnPush // false)"'

echo
echo "[!] scanType BASIC with scanOnPush true is NOT equivalent to ENHANCED. Basic covers OS"
echo "    packages only and never rescans; Enhanced covers language packages too and rescans"
echo "    continuously as new vulnerabilities appear."
```

#### Query 3 — Confirm coverage from findings, not from configuration

```bash
REPO="${1:?repository name from Query 1}"
REGION="${AWS_REGION:-us-east-1}"

# Three states all present as "scanning is on". Only the findings distinguish them.
aws ecr describe-images --repository-name "$REPO" --region "$REGION" \
  --query 'sort_by(imageDetails,&imagePushedAt)[-10:].[imageTags[0],imageDigest,imagePushedAt]' \
  --output text 2>/dev/null | while IFS=$'\t' read -r TAG DIGEST PUSHED; do
    [ -z "$DIGEST" ] && continue
    N="$(aws ecr describe-image-scan-findings --repository-name "$REPO" \
          --image-id "imageDigest=${DIGEST}" --region "$REGION" \
          --query 'imageScanFindings.findingSeverityCounts' --output json 2>/dev/null)"
    if [ -z "$N" ] || [ "$N" = "null" ] || [ "$N" = "{}" ]; then
      echo "[!] ${TAG:-<untagged>}  pushed=$PUSHED  NO FINDINGS — unscanned, archived, or arrived during a gap"
    else
      echo "[OK] ${TAG:-<untagged>}  pushed=$PUSHED  findings=$N"
    fi
  done

echo
echo "[!] An image with no findings in a repository whose scanOnPush reads TRUE is the anomaly."
echo "    It arrived while scanning was off, or the registry tier was switched and its findings"
echo "    were discarded, or it is archived — and archiving changes no configuration at all."
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

Look for `PutImage` after the scanning change, and for `GetRegistryScanningConfiguration` or
`DescribeRepositories` before it — reading the posture before changing it is the reconnaissance half.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Restore scanning first — it is one call. But note that restoring it does **not** scan what arrived
while it was off, which is Step 3 and the part most likely to be skipped.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 1 shows
`REGISTRY -> BASIC`, the finding history for the entire registry has already been discarded and
cannot be recovered by switching back — AWS restores previous scans only if you return to the
*previous* tier, and the findings generated in between are gone either way. Switch back, then treat
every image as unscanned until Step 3 completes.

#### Step 1 — Restore the scanning configuration

```bash
REPO="${1:?repository name, or 'registry' for the registry-wide setting}"
REGION="${AWS_REGION:-us-east-1}"

if [ "$REPO" = "registry" ]; then
  echo "[!] Restoring ENHANCED scanning registry-wide. Existing BASIC findings are discarded by the"
  echo "    switch — that is unavoidable and is the cost of the original change, not of this fix."
  aws ecr put-registry-scanning-configuration --region "$REGION" \
    --scan-type ENHANCED \
    --rules '[{"scanFrequency":"CONTINUOUS_SCAN","repositoryFilters":[{"filter":"*","filterType":"WILDCARD"}]}]' \
    && echo "[OK] registry scanning restored to ENHANCED with continuous rescanning"
else
  aws ecr put-image-scanning-configuration --repository-name "$REPO" --region "$REGION" \
    --image-scanning-configuration scanOnPush=true \
    && echo "[OK] scanOnPush restored on $REPO"
fi
```

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

#### Step 3 — Scan what arrived during the gap

```bash
REPO="${1:?repository name}"
GAP_START="${2:?timestamp scanning was disabled}"
REGION="${AWS_REGION:-us-east-1}"

# Re-enabling scanOnPush scans FUTURE pushes only. Nothing backfills, so images that arrived in the
# gap stay unscanned indefinitely unless each is triggered by hand.
aws ecr describe-images --repository-name "$REPO" --region "$REGION" --output json 2>/dev/null \
| jq -r --arg s "$GAP_START" '.imageDetails[]
    | select(.imagePushedAt > $s) | .imageDigest' \
| while read -r D; do
    [ -z "$D" ] && continue
    aws ecr start-image-scan --repository-name "$REPO" --image-id "imageDigest=${D}" \
      --region "$REGION" >/dev/null 2>&1 \
      && echo "[OK] scan started for ${D:0:19}…" \
      || echo "[!] could not start a scan for ${D:0:19}… (Enhanced scanning triggers automatically)"
  done
```

This is the step that closes the gap, and it is the one most likely to be skipped because the
configuration already looks correct after Step 1.

#### Step 4 — Establish what was pushed while scanning was off

Every image that arrived during the gap entered with no finding attached. Cross-reference Query 1's
`image pushed` lines against the gap window: each is an image that no control inspected, and if any
came from a principal outside the deployment path, this is not a scanning incident but a supply-chain
one — go to `../ecr.stealth.malicious-image-pushed/`.

---

## 4. Eradication

### Remove Attacker Access

#### Export scan findings outside ECR

This is the eradication step that survives the technique. Switching tiers discards findings inside
AWS, so an exported history is the only record of what was known before — and without it, "were
these images clean last week" is unanswerable after a single registry call.

#### Prefer Enhanced scanning with continuous rescanning

Basic scans on push and never again, so an image clean at push time stays "clean" in ECR's view
forever regardless of what is disclosed later. Enhanced rescans continuously and emits to
EventBridge, which also gives a signal path independent of the registry configuration.

#### Deny scanning configuration changes outside the provisioning path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyScanningConfigurationChanges",
  "Effect": "Deny",
  "Action": ["ecr:PutImageScanningConfiguration", "ecr:PutRegistryScanningConfiguration"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourProvisioningRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone including the pipeline. The registry-level action is included deliberately: denying only the
per-repository call leaves the more consequential switch available.

#### Gate deployment on scan results, not on scanning being enabled

A pipeline that checks `scanOnPush` is true is satisfied by all three of the states that produce no
findings. One that requires a *findings result* for the digest it is about to deploy is not.

---

## 5. Recovery

### Restore Clean State

#### Verify the scanning posture across the region

```bash
REGION="${AWS_REGION:-us-east-1}"

TYPE="$(aws ecr get-registry-scanning-configuration --region "$REGION" \
         --query 'scanningConfiguration.scanType' --output text 2>/dev/null)"
case "$TYPE" in
  ENHANCED) echo "[OK] registry scanType is ENHANCED" ;;
  BASIC)    echo "[FAIL] registry scanType is BASIC — OS packages only, no continuous rescanning" ;;
  *)        echo "[!] could not determine registry scanType ($TYPE)" ;;
esac

FAIL=0
aws ecr describe-repositories --region "$REGION" --output json 2>/dev/null \
| jq -r '.repositories[] | select((.imageScanningConfiguration.scanOnPush // false) == false)
         | "[FAIL] \(.repositoryName) scanOnPush is false"' | tee /tmp/ecr-scan-off.txt
[ -s /tmp/ecr-scan-off.txt ] && FAIL=1
[ "$FAIL" -eq 0 ] && echo "[OK] every repository has scanOnPush enabled"
```

#### Verify images from the gap now have findings

```bash
REPO="${1:?repository name}"
GAP_START="${2:?timestamp scanning was disabled}"
REGION="${AWS_REGION:-us-east-1}"

aws ecr describe-images --repository-name "$REPO" --region "$REGION" --output json 2>/dev/null \
| jq -r --arg s "$GAP_START" '.imageDetails[] | select(.imagePushedAt > $s) | .imageDigest' \
| while read -r D; do
    [ -z "$D" ] && continue
    N="$(aws ecr describe-image-scan-findings --repository-name "$REPO" \
          --image-id "imageDigest=${D}" --region "$REGION" \
          --query 'imageScanFindings.findingSeverityCounts' --output json 2>/dev/null)"
    if [ -z "$N" ] || [ "$N" = "null" ]; then
      echo "[FAIL] ${D:0:19}… still has no findings — the backfill scan did not run or is pending"
    else
      echo "[OK] ${D:0:19}… scanned"
    fi
  done
```

Configuration being correct is not recovery here. The images that arrived in the gap are the reason
the incident mattered, and they stay unscanned until this reports clean.

#### Confirm the corrected detection fires

```bash
REPO="${1:?a NON-PRODUCTION repository name}"
REGION="${AWS_REGION:-us-east-1}"

# Exercise the per-repository setting rather than the registry switch: the registry call would
# discard real findings across the whole registry, which is not an acceptable test.
aws ecr put-image-scanning-configuration --repository-name "$REPO" --region "$REGION" \
  --image-scanning-configuration scanOnPush=false >/dev/null 2>&1 \
  && echo "[OK] scanOnPush disabled on $REPO — expect the HIGH rule within 15 min"

sleep 60
aws ecr put-image-scanning-configuration --repository-name "$REPO" --region "$REGION" \
  --image-scanning-configuration scanOnPush=true >/dev/null 2>&1 \
  && echo "[OK] restored"
echo "[!] Do NOT test the registry-level switch. It discards every established finding in the"
echo "    registry, and that loss is not reversible by switching back."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Repository setting, or registry switch? | They differ by orders of magnitude: one repository stops scanning new images; the registry switch discards every existing finding and reduces coverage everywhere. |
| Did `scanOnPush` still read true afterwards? | If the registry was switched, it will — which is why a configuration check passes and a findings check does not. |
| Was an image pushed during the gap? | That is what makes this a supply-chain incident rather than a configuration one. |
| Were the gap images backfill-scanned? | Re-enabling scans future pushes only. Nothing backfills. |
| Were findings exported anywhere outside ECR? | If not, "were these clean last week" is unanswerable after a single registry call. |
| Does the deployment pipeline check the setting or the findings? | A pipeline checking the setting is satisfied by all three no-findings states. |

### Recommended Guardrails

**Watch `PutRegistryScanningConfiguration`.** It is the consequential call and the source pack
watches it nowhere.

**Export findings outside ECR.** Switching tiers discards them inside AWS, and the export is the only
thing that survives.

**Gate deployment on a findings result for the digest**, not on scanning being enabled. Three
different states report as enabled and produce nothing.

**Prefer Enhanced with continuous rescanning.** Basic scans once at push and never revisits, so a
disclosure after the push never surfaces.

**Backfill after any gap.** Re-enabling is not remediation; the images that arrived while it was off
are the reason the incident mattered.

### Technique Reference

**T1685 — Disable or Modify Tools.** Verified live at https://attack.mitre.org/techniques/T1685/ on
2026-08-30. An image scanner is a security tool, and AWS's own description of the technique names
*"endpoint detection and response (EDR) tools, intrusion detection systems (IDS), antivirus, logging
agents, sensors"*.

There is **no** cloud-security-tool sub-technique. `T1685.001` is Windows Event Log, `.002` is Cloud
Log, `.003` is Modify or Spoof Tool UI, `.004` is Linux Audit System Log, and `.005`/`.006` clear
logs — so the **parent** is the correct mapping here.

The source rule maps to `T1578 — Modify Cloud Compute Infrastructure`, and ECR is a registry rather
than compute.

AWS references relied on throughout, all verified 2026-08-30:

- ECR image scanning — the two tiers, their configuration APIs, and the statement that switching
  between them discards established scans:
  https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html

Service-wide verified behaviour shared by every `ecr.*` playbook is in `../_ground-truth/ecr.md`.

### Residual Risk

**Archiving removes an image from scanning and changes no configuration.** AWS: *"Archived images
cannot be scanned. Archived images must be restored before they can be scanned."* No scanning event
accompanies it, so nothing in this directory sees it.

**Switching back does not restore the findings generated in between.** AWS returns previously
established scans if you return to the previous tier, but anything found while the other tier was
active is gone. The window is unrecoverable in both directions.

**Basic scanning never rescans.** An image clean at push time remains "clean" in ECR's view
indefinitely, regardless of what is disclosed about its packages afterwards. That is a permanent
property of the tier rather than a misconfiguration.

**A clean scan is not an integrity check.** Scanning reports known CVEs in packages and does not
detect an implanted backdoor. Disabling it removes a control and signals intent; it does not follow
that scanning would have caught what was pushed.
