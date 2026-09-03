# IR Playbook: ECR Images Destroyed — `BatchDeleteImage`, `DeleteRepository` and lifecycle expiry

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Impact — container images are removed from the registry, immediately or on a schedule, with no recovery path inside AWS |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | Critical for a repository deletion or destruction across several repositories; high for image deletion; medium for a lifecycle policy, which the preview resolves. The source pack rates all three P4. |
| MITRE Tactics | Impact |
| MITRE Techniques | T1485 |
| Services in Scope | ECR, ECR Public, ECS, EKS, CloudTrail |

**What the technique does:** the actor removes images. There are three ways and they differ mainly
in when the loss lands:

| Call | Effect |
|---|---|
| `BatchDeleteImage` | Images removed now |
| `DeleteRepository` (with or without `force`) | Repository and its images removed now |
| `PutLifecyclePolicy` | Images expire days later, on a schedule, with no event naming them |

**Nothing deleted from ECR is recoverable.** There is no versioning, no recycle bin and no undelete.
Once a digest is gone, the layers are gone, and the only recovery is rebuilding from source.

**Why the usual reflexes miss it.** The first is requiring `force: true`, which the source rule does
— `DeleteRepository` succeeds without it on an empty repository, so deleting the images first
reaches the same end state and never sets the flag. The second is treating a lifecycle policy as
configuration rather than destruction; it is the quietest of the three and the source pack files it
under privilege escalation. The third is expecting an outage immediately: a running container keeps
going from local layers, so the impact surfaces at the next scale-out or restart, often days later.
The fourth is reaching for restore, which does not exist here.

**Detection thesis:** cover both repository-deletion paths, treat the lifecycle policy as delayed
destruction and resolve it with the preview API, and rate on breadth across repositories.

**Adjacent playbooks.** An image pushed rather than removed is
`../ecr.stealth.malicious-image-pushed/`; pulled, `../ecr.collection.excessive-images-pulled/`. Who
may delete at all is `../ecr.privilege-escalation.repository-policy-applied/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. ECR is **regional** and `ecr-public` operates from
`us-east-1`.

**A mapping from image to consumer** — which task definitions, deployments and pipelines reference
each repository. This is the prerequisite the whole response depends on: the registry cannot tell
you what depended on a deleted image, and without the mapping the blast radius is unknowable until
something fails to start.

**Reproducible builds, or at least retained build artefacts.** Rebuild is the only recovery
available. An estate that can rebuild a digest from a commit recovers in minutes; one that cannot has
lost the image permanently.

**A recorded lifecycle policy per repository.** A policy change is only visible as a difference, and
AWS keeps no previous version of it.

**Alerting (must be pre-configured)**

- **`DeleteRepository` on any repository, forced or not → P0**
- **Images destroyed across three or more repositories by one principal within an hour → P0**
- **A lifecycle policy applied that targets tagged images with a low retention count → P0**

**Response Tooling**

An IAM principal that can call `ecr describe-images`, `start-lifecycle-policy-preview`,
`get-lifecycle-policy`, `put-lifecycle-policy` and `describe-repositories` outside the change
pipeline, in every region.

Access to the build pipeline and source repository for anything that needs rebuilding.

**Known IOC Baselines**

The roles that own repository lifecycle, populating `known_provisioners`.

The teardown schedule for non-production environments — the only routine explanation for a
repository deletion.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | Images or repositories destroyed across three or more repositories by one principal within an hour | Correlation rule | T1485 |
| P0 | `DeleteRepository` succeeds — with `force`, or without it after the images were deleted first | CloudTrail | T1485 |
| P0 | `PutLifecyclePolicy` whose preview shows tagged production images would be expired | CloudTrail + `StartLifecyclePolicyPreview` | T1485 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | `BatchDeleteImage` by a principal outside the provisioning path | CloudTrail | T1485 |
| P2 | `PutLifecyclePolicy` by a principal outside the provisioning path — preview before rating | CloudTrail | T1485 |
| P2 | `DeleteLifecyclePolicy` — removing a retention rule is not destruction, but it changes what the next policy replaces | CloudTrail | T1485 |

### Detection Rule Quality Notes

All three source rules are threshold queries and fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `DeleteRepository` requires `force: true` | The call succeeds **without** force on an empty repository, so deleting the images first reaches the same end state and never sets the flag. The rule covers one path of two | Both paths matched; the flag is reported rather than required |
| The lifecycle rule has no content check | A lifecycle policy is ordinary cost management. Firing on every policy makes the rule noise; ignoring it misses destruction on a timer | Medium severity plus a mandatory `StartLifecyclePolicyPreview` triage step, which reports exactly what a policy would remove without removing it |
| Three rules, three group-by fields | Two group by `userIdentity.principalId` and one by `repositoryName` plus `userIdentity.arn`, so they cannot be correlated with each other and the pack has no destruction-at-breadth signal | One grouping across all three, and a `value_count` correlation on distinct repositories |
| All three rated P4 | Nothing in ECR is recoverable. A P4 on an irreversible action is below the threshold at which anyone acts while acting is still useful | Critical for repository deletion and breadth, high for image deletion, medium for a lifecycle policy |
| MITRE: `T1578` on repository deletion, `T1484` on the lifecycle policy | ECR is a registry, not compute; and a retention rule is not directory or tenant policy | `T1485 — Data Destruction` for all three, which is the source's own mapping for image deletion |
| Each rule excludes the same named human by ARN | A personal allowlist compiled into the detection logic for a whole service | A populated provisioner list a responder can read and change |

**One thing the source got right:** the `BatchDeleteImage` rule includes `AssumedRole` in its
identity filter, where the push and pull rules in the same pack exclude it. The pack is inconsistent
with itself and this rule is on the correct side of that inconsistency.

**Recommended detection — three shapes of destruction, rated by permanence and breadth.**

```yaml
# Container images destroyed in ECR (T1485)
#
# MERGE TEST — THREE SOURCE RULES, ONE USE CASE, BECAUSE DESTRUCTION HAS THREE SHAPES.
#   BatchDeleteImage       removes specified images now
#   DeleteRepository force removes the repository AND its images now
#   PutLifecyclePolicy     expires images on a schedule — destruction on a timer
# They share one response: establish what was destroyed, whether it is recoverable, and what
# depended on it. The third is the quietest and the only one the source pack rates as a privilege
# escalation rather than an impact.
#
# NOTHING DELETED FROM ECR IS RECOVERABLE. There is no versioning, no recycle bin and no undelete —
# unlike S3, where a delete marker can be removed. Once an image digest is gone the layers are gone,
# and the only recovery is rebuilding from source. That is why the response prioritises establishing
# WHAT was destroyed over restoring it.
#
# THE `force: true` FILTER IS A NARROW SLICE OF THE TECHNIQUE. `DeleteRepository` succeeds WITHOUT
# force when the repository is empty — so deleting every image first and then the repository
# achieves the same end state and never sets the flag. Both paths are matched below.
#
# THE LIFECYCLE RULE HAS NO CONTENT CHECK AND IS RATED AS PRIVILEGE ESCALATION. A lifecycle policy is
# ordinary cost management; an aggressive one deletes images days later with no further event naming
# them. The rule fires on every policy equally and maps to `T1484 — Domain or Tenant Policy
# Modification`, which is about directory and tenant policy, not a registry retention rule.
#
# AND THE THREE RULES GROUP BY DIFFERENT FIELDS — two by `userIdentity.principalId`, one by
# `repositoryName` plus `userIdentity.arn`. Sibling rules over the same resource at two
# granularities cannot be correlated with each other, which is why the pack has no
# destruction-at-breadth signal.
title: ECR repository deleted
id: 2e91c740-58b3-4d06-a9f2-71d0e4a86c35
name: ecr_repository_deleted
status: experimental
description: >-
  A successful DeleteRepository. With force it removes the repository and every image in it; without
  force it succeeds only on an empty repository, which an actor reaches by deleting the images first
  — so both paths are matched and the flag is reported rather than required. Nothing deleted from
  ECR is recoverable: there is no versioning and no undelete.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_DeleteRepository.html
  - https://attack.mitre.org/techniques/T1485/
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource:
      - 'ecr.amazonaws.com'
      - 'ecr-public.amazonaws.com'
    eventName: 'DeleteRepository'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the roles that own repository lifecycle.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    An environment teardown, which legitimately removes repositories. It should correlate with the
    rest of the environment disappearing; a repository deletion with nothing around it is the
    finding.
level: critical
---
title: ECR images deleted
id: 8d34a0f6-2c17-4b95-8e60-b31f752ce9a4
name: ecr_images_deleted
status: experimental
description: >-
  A successful BatchDeleteImage from a principal outside the provisioning path. Deleting the last
  tag referencing a digest removes the image itself, and nothing in ECR is recoverable afterwards.
  Note this rule's source sibling correctly included AssumedRole in its identity filter where the
  push and pull rules in the same pack did not — the pack is inconsistent with itself.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_BatchDeleteImage.html
  - https://attack.mitre.org/techniques/T1485/
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource:
      - 'ecr.amazonaws.com'
      - 'ecr-public.amazonaws.com'
    eventName: 'BatchDeleteImage'
  success:
    errorCode: null
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    Manual cleanup of untagged images, which is common and legitimate. The repository and the count
    are what distinguish it — a handful of untagged digests in one repository is housekeeping, and
    tagged images across several repositories is not.
level: high
---
title: ECR lifecycle policy applied
id: 6b05e2d9-91fa-4c38-b7e1-40d3859ac761
name: ecr_lifecycle_policy_applied
status: experimental
description: >-
  A successful PutLifecyclePolicy. This is destruction on a timer: the policy deletes images days
  later, on a schedule, with no further event naming what went. A lifecycle policy is also ordinary
  cost management, so this cannot be rated on the event alone — the triage step is running
  StartLifecyclePolicyPreview, which reports exactly which images the policy would remove without
  removing them.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutLifecyclePolicy.html
  - https://attack.mitre.org/techniques/T1485/
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecr.amazonaws.com'
    eventName: 'PutLifecyclePolicy'
  success:
    errorCode: null
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/iac-deploy'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    Genuine cost management, which is the common case. Rated medium for that reason — the preview
    resolves it in one call, and an aggressive expiry from a non-provisioning principal is the
    finding rather than the policy's existence.
level: medium
---
title: ECR images destroyed across multiple repositories by one principal
id: f7280caa-4e16-49b3-85d0-c6a19e037b42
status: experimental
description: >-
  One principal destroyed images in three or more distinct repositories within an hour. A single
  deletion has a housekeeping reading; destruction spread across repositories does not, and it is
  the shape the source pack cannot produce because its three destruction rules group by different
  fields and cannot be correlated with each other.
references:
  - https://attack.mitre.org/techniques/T1485/
tags:
  - attack.impact
  - attack.t1485
correlation:
  type: value_count
  rules:
    - ecr_image_destruction
  group-by:
    - userIdentity.arn
  timespan: 1h
  condition:
    gte: 3
    field: requestParameters.repositoryName
falsepositives:
  - >-
    An environment teardown removing many repositories at once. Allowlist the teardown role on the
    base rule rather than raising the threshold — three repositories is already generous for a
    human operator.
level: critical
---
title: ECR image or repository destruction
id: 05c9b3e1-7a24-4f80-91d6-2e8407fb5a63
name: ecr_image_destruction
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. Any successful call that
  removes images or a repository. Untagged-image cleanup produces these routinely.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_BatchDeleteImage.html
tags:
  - attack.impact
  - attack.t1485
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource:
      - 'ecr.amazonaws.com'
      - 'ecr-public.amazonaws.com'
    eventName:
      - 'BatchDeleteImage'
      - 'DeleteRepository'
  success:
    errorCode: null
  condition: selection and success
level: informational
```

What this set structurally cannot do: tell you what depended on the destroyed images. That mapping
lives in task definitions and cluster manifests, and §2 Query 4 goes there for it.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> ECR is **regional** and `ecr-public` operates from `us-east-1` — run these per region.

Run Query 1 first; it establishes which of the three shapes this is, and they diverge immediately.

#### Query 1 — Reconstruct: which shape, and how wide

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in BatchDeleteImage DeleteRepository PutLifecyclePolicy DeleteLifecyclePolicy; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      | .requestParameters as $r
      # DeleteRepository succeeds WITHOUT force on an empty repository — deleting the images first
      # reaches the same end state and never sets the flag the source rule requires.
      | (if .eventName == "DeleteRepository" then
             (if ($r.force == true or $r.force == "true") then "REPO-DELETED(forced)"
              else "REPO-DELETED(unforced — images were already gone)" end)
         elif .eventName == "BatchDeleteImage" then "IMAGES-DELETED"
         elif .eventName == "PutLifecyclePolicy" then "LIFECYCLE-SET(delayed destruction)"
         else "lifecycle-removed" end) as $kind
      | "\(.eventTime)  \($kind)  repo=\($r.repositoryName // "-")  by=\(.userIdentity.arn)  ip=\(.sourceIPAddress)"'
done | sort
```

Count **distinct repositories** across the whole output for one principal. A `LIFECYCLE-SET` line is
the one to take most seriously despite deleting nothing at the time — go straight to Query 2. An
`IMAGES-DELETED` followed by `REPO-DELETED(unforced)` on the same repository is the force-flag
bypass.

#### Query 2 — What would the lifecycle policy actually remove

```bash
REPO="${1:?repository name from Query 1}"
REGION="${AWS_REGION:-us-east-1}"

echo "=== The policy now in force ==="
aws ecr get-lifecycle-policy --repository-name "$REPO" --region "$REGION" \
  --query 'lifecyclePolicyText' --output text 2>/dev/null \
| python3 -m json.tool 2>/dev/null || echo "  (no lifecycle policy on this repository)"

echo
echo "=== What it WOULD delete — this removes nothing ==="
# StartLifecyclePolicyPreview evaluates the policy against the current images and reports the
# result without applying it. This is the authority; any heuristic over the policy text is not.
aws ecr start-lifecycle-policy-preview --repository-name "$REPO" --region "$REGION" \
  >/dev/null 2>&1 && sleep 5
aws ecr get-lifecycle-policy-preview --repository-name "$REPO" --region "$REGION" --output json 2>/dev/null \
| jq -r '"  status: \(.status)",
         "  images that would be expired: \((.previewResults // []) | length)",
         ((.previewResults // [])[] | "    \(.imageTags // ["<untagged>"] | join(","))  \(.imageDigest[0:19])…")'

echo
echo "[!] A preview listing TAGGED images is the finding. Untagged-image expiry is normal hygiene;"
echo "    expiring tagged images is removing the things deployments reference by name."
```

#### Query 3 — What is gone, and can it be rebuilt

```bash
REPO="${1:?repository name}"
REGION="${AWS_REGION:-us-east-1}"

echo "=== What remains in the repository ==="
aws ecr describe-images --repository-name "$REPO" --region "$REGION" \
  --query 'sort_by(imageDetails,&imagePushedAt)[].[imageTags[0],imageDigest,imagePushedAt]' \
  --output text 2>/dev/null | sed 's/^/  /' \
  || echo "  [!] repository does not exist — it was deleted, not emptied"

cat <<'NOTE'

[!] ECR has NO versioning, NO recycle bin and NO undelete. Whatever is missing is permanently gone
    from AWS. The only recovery is rebuilding from source, so the questions are:

      [ ] does the source commit for each missing tag still exist
      [ ] can the build pipeline reproduce that digest
      [ ] is any copy held elsewhere — a mirror, a developer machine, another region

    If none of those hold, record the image as unrecoverable rather than pending.
NOTE
```

#### Query 4 — What depended on the destroyed images

```bash
REPO_URI="${1:?repository URI, e.g. 123456789012.dkr.ecr.us-east-1.amazonaws.com/myrepo}"
REGION="${AWS_REGION:-us-east-1}"

echo "=== ECS task definitions referencing this repository ==="
aws ecs list-task-definitions --region "$REGION" --status ACTIVE \
  --query 'taskDefinitionArns[]' --output text 2>/dev/null | tr '\t' '\n' | while read -r TD; do
    [ -z "$TD" ] && continue
    aws ecs describe-task-definition --task-definition "$TD" --region "$REGION" --output json 2>/dev/null \
    | jq -r --arg u "$REPO_URI" --arg t "$TD" \
        '.taskDefinition.containerDefinitions[] | select(.image | startswith($u)) | "  \($t)  \(.image)"'
  done

echo
echo "[!] A RUNNING container survives its image being deleted — it keeps going from local layers"
echo "    until it is restarted or rescheduled. So the impact is DEFERRED: it presents as a failure"
echo "    to launch at the next scale-out or deployment, often days later. Anything listed above is"
echo "    a future outage, not a current one."
echo "[!] EKS is not covered here. Query it separately for the same image URI."
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Containment here is unusual: the destruction has already happened and cannot be undone, so the
priority is stopping *further* destruction and preventing the scheduled kind from ever running.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 2 shows a lifecycle
policy that would expire tagged images, remove that policy before anything else. It is the only part
of this incident that has not happened yet, and it is the only part you can still prevent.

#### Step 1 — Stop the scheduled destruction

```bash
REPO="${1:?repository name}"
REGION="${AWS_REGION:-us-east-1}"

# Preserve the policy first — it is evidence, and AWS keeps no previous version of it.
aws ecr get-lifecycle-policy --repository-name "$REPO" --region "$REGION" --output json \
  > "./evidence-${REPO//\//_}-lifecycle.json" 2>/dev/null \
  && echo "[OK] policy preserved at ./evidence-${REPO//\//_}-lifecycle.json"

echo "[!] Deleting the policy stops future expiry. It does NOT restore anything already expired."
read -r -p "Delete the lifecycle policy on ${REPO}? [y/N] " ANS
[ "$ANS" = "y" ] && aws ecr delete-lifecycle-policy --repository-name "$REPO" --region "$REGION" \
  && echo "[OK] lifecycle policy removed from $REPO"
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

Containment is more clearly correct here than in most playbooks: there is no operational workflow
that legitimately destroys images outside the deployment pipeline, so revoking this principal is
unlikely to break something important.

#### Step 3 — Protect what remains

```bash
REGION="${AWS_REGION:-us-east-1}"

# Deletion cannot be undone, so the useful action is making the remaining images harder to remove.
# Tag immutability does not prevent deletion, but it prevents the quieter variant where a tag is
# repointed at a different digest and the original becomes unreferenced.
for R in $(aws ecr describe-repositories --region "$REGION" \
            --query 'repositories[].repositoryName' --output text 2>/dev/null | tr '\t' '\n'); do
  [ -z "$R" ] && continue
  M="$(aws ecr describe-repositories --repository-names "$R" --region "$REGION" \
        --query 'repositories[0].imageTagMutability' --output text 2>/dev/null)"
  [ "$M" = "MUTABLE" ] && echo "[!] $R is MUTABLE — consider IMMUTABLE for production repositories"
done

echo
echo "[!] The durable protection for deletion itself is a repository policy or an SCP denying"
echo "    ecr:BatchDeleteImage and ecr:DeleteRepository outside the provisioning role — see §4."
```

#### Step 4 — Scope the deferred outage

Query 4 lists what references the destroyed repository. None of those are failing yet — a running
container keeps going from local layers — so this step is about getting ahead of the failure rather
than responding to it. For each consumer, either rebuild and re-push the image, or repoint it at a
surviving digest, **before** the next deployment or scale-out forces the issue.

---

## 4. Eradication

### Remove Attacker Access

#### Rebuild what can be rebuilt, and record what cannot

Recovery is a build-pipeline exercise, not an AWS one. For each destroyed tag: does the source commit
exist, can the pipeline reproduce it, and is a copy held anywhere else — a mirror, another region, a
developer machine. Anything failing all three is permanently lost and belongs in the report as such
rather than as an open remediation item.

#### Deny destruction outside the provisioning path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyRegistryDestruction",
  "Effect": "Deny",
  "Action": ["ecr:BatchDeleteImage", "ecr:DeleteRepository", "ecr:PutLifecyclePolicy",
             "ecr:DeleteLifecyclePolicy", "ecr-public:BatchDeleteImage",
             "ecr-public:DeleteRepository"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourProvisioningRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone including the pipeline. `PutLifecyclePolicy` is included deliberately: denying immediate
deletion while leaving the scheduled kind available closes one door and not the other.

#### Mirror production images outside the account

Because AWS holds no recoverable copy, the only real protection against this technique is a copy it
does not control — a second registry, a different account, or an artefact store. This is the single
change that converts "permanently lost" into "restore from the mirror", and no detection substitutes
for it.

#### Review lifecycle policies as security configuration

They are usually owned by whoever cares about storage cost, and reviewed as a billing matter. A
policy that expires tagged images is a retention decision with an availability consequence, and it
should be read by the same people who read the repository policy.

---

## 5. Recovery

### Restore Clean State

#### Verify no lifecycle policy will expire tagged images

```bash
REGION="${AWS_REGION:-us-east-1}"
FAIL=0

for R in $(aws ecr describe-repositories --region "$REGION" \
            --query 'repositories[].repositoryName' --output text 2>/dev/null | tr '\t' '\n'); do
  [ -z "$R" ] && continue
  P="$(aws ecr get-lifecycle-policy --repository-name "$R" --region "$REGION" \
        --query 'lifecyclePolicyText' --output text 2>/dev/null)"
  [ -z "$P" ] && continue
  if printf '%s' "$P" | grep -q '"tagStatus":[[:space:]]*"tagged"\|"tagStatus":[[:space:]]*"any"'; then
    echo "[FAIL] $R has a lifecycle policy targeting tagged images — run the preview"
    FAIL=1
  else
    echo "[OK] $R lifecycle policy targets untagged images only"
  fi
done
[ "$FAIL" -eq 0 ] && echo "[OK] no policy targets tagged images in $REGION"
```

Targeting `untagged` is normal hygiene. Targeting `tagged` or `any` means the policy will remove
images that deployments reference by name, and the preview should be run on every one of those.

#### Verify the consumers of destroyed repositories have a working image

```bash
REPO_URI="${1:?repository URI that was destroyed}"
REGION="${AWS_REGION:-us-east-1}"

REPO="${REPO_URI##*/}"
if aws ecr describe-repositories --repository-names "$REPO" --region "$REGION" >/dev/null 2>&1; then
  N="$(aws ecr describe-images --repository-name "$REPO" --region "$REGION" \
        --query 'length(imageDetails)' --output text 2>/dev/null)"
  [ "${N:-0}" -gt 0 ] && echo "[OK] $REPO exists with $N image(s)" \
                      || echo "[FAIL] $REPO exists but is EMPTY — consumers will fail to launch"
else
  echo "[FAIL] $REPO does not exist — every consumer will fail at its next scale-out"
fi
```

#### Confirm the corrected detection fires

```bash
REPO="${1:?a NON-PRODUCTION repository name}"
REGION="${AWS_REGION:-us-east-1}"

# Exercise the LIFECYCLE path, which is the shape the source pack files under privilege escalation
# and which deletes nothing at the time. Targeting untagged images with a long expiry means the
# policy is harmless even if left in place accidentally.
aws ecr put-lifecycle-policy --repository-name "$REPO" --region "$REGION" \
  --lifecycle-policy-text '{"rules":[{"rulePriority":1,"description":"detection-test","selection":{"tagStatus":"untagged","countType":"sinceImagePushed","countUnit":"days","countNumber":3650},"action":{"type":"expire"}}]}' \
  >/dev/null 2>&1 && echo "[OK] lifecycle policy applied — expect the MEDIUM rule within 15 min"

sleep 60
aws ecr delete-lifecycle-policy --repository-name "$REPO" --region "$REGION" >/dev/null 2>&1 \
  && echo "[OK] test policy removed"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| Which of the three shapes was it? | They diverge immediately: two have already happened, and the lifecycle one has not yet. |
| Was `DeleteRepository` unforced after the images were deleted? | That is the force-flag bypass, and it means the source rule would not have fired. |
| What did the preview say the lifecycle policy would remove? | It is the authority, and it distinguishes cost management from destruction on a timer. |
| Can each destroyed image be rebuilt from source? | Recovery is a build exercise; anything failing it is permanently lost and should be reported as such. |
| What referenced the destroyed repository? | The outage is deferred to the next scale-out, so this is a list of future failures rather than current ones. |
| Is there a copy outside the account? | The only real protection, and its absence is usually the root finding. |

### Recommended Guardrails

**Mirror production images outside the account.** AWS holds no recoverable copy, so this is the one
change that converts permanent loss into a restore. Everything else here is detection.

**Match `DeleteRepository` with and without `force`.** Requiring the flag covers one of two paths to
the same end state.

**Treat lifecycle policies as security configuration.** They are usually reviewed as a billing
matter, and a policy expiring tagged images is a retention decision with an availability
consequence.

**Run the preview before rating any lifecycle finding.** It reports exactly what a policy would
remove, without removing it, and no heuristic over the policy text is as good.

**Rate irreversible actions above P4.** Nothing in ECR is recoverable, so a rating that defers a look
until later defers it past the point where anything could have been done.

### Technique Reference

**T1485 — Data Destruction.** Verified live at https://attack.mitre.org/techniques/T1485/ on
2026-08-30. This is the source's own mapping for `BatchDeleteImage` and is correct for all three
shapes.

The source pack maps repository deletion to `T1578 — Modify Cloud Compute Infrastructure` (ECR is a
registry, not compute) and the lifecycle policy to `T1484 — Domain or Tenant Policy Modification` (a
retention rule is not directory or tenant policy). Both are wrong in the same direction: they name
the place rather than the act.

AWS references relied on throughout, all verified 2026-08-30:

- `DeleteRepository`: https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_DeleteRepository.html
- `BatchDeleteImage`: https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_BatchDeleteImage.html
- `PutLifecyclePolicy`: https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutLifecyclePolicy.html

Service-wide verified behaviour shared by every `ecr.*` playbook is in `../_ground-truth/ecr.md`.

### Residual Risk

**There is no recovery inside AWS.** No versioning, no recycle bin, no undelete. Every other
destruction playbook in this set has a restore path; this one has a rebuild path, and only if the
source and pipeline survived.

**The lifecycle variant is detectable only at configuration time.** Once the policy is in place the
expiry happens on AWS's schedule with no event naming the images, so an estate that misses the
`PutLifecyclePolicy` event will see images disappear with nothing in CloudTrail to explain it.

**The outage is deferred and will be misattributed.** A running container survives its image being
deleted, so the failure surfaces at the next scale-out — potentially days later, and to a team that
has no reason to connect it to a registry event.

**`ecr-public` deletion is equally permanent and less monitored.** The public registry operates from
`us-east-1` only, so an estate whose trail is regional elsewhere sees none of it.
