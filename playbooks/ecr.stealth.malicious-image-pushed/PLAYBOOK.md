# IR Playbook: Malicious Image Pushed to ECR — supply-chain implant via `ecr:PutImage`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Persistence — a container image is pushed by a principal outside the deployment path, so everything downstream that pulls the tag runs attacker-supplied code |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. Critical in effect once anything pulls the image, and a push to the **public** registry cannot be undone by deleting it. The source rule ships as a building block — not rated at all. |
| MITRE Tactics | Persistence |
| MITRE Techniques | T1525 |
| Services in Scope | ECR, ECR Public, ECS, EKS, IAM, CloudTrail |

**What the technique does:** the actor pushes an image. That is the whole act — no second step, no
precondition. Every task, pod or node that subsequently pulls the tag runs the image, under whatever
role that workload holds. One image is the incident.

**Why the usual reflexes miss it.** The first is the identity filter: the source rule matches
`userIdentity.type:"iamuser"` — lowercase, so it cannot fire at all, and corrected it would still
exclude `AssumedRole`, which is every CI/CD pipeline. The second is treating this as a volume
problem: five pushes in fifteen minutes is too high to catch one malicious image and too low to
avoid a normal CI run pushing three tags for one build. The third is treating the public registry
like the private one — deleting a public image does not un-distribute it. The fourth is looking for
the malicious content in the event; `PutImage` registers a manifest and says nothing about the
layers.

**Detection thesis:** the deployment-role allowlist is the discriminator, not the identity type and
not a threshold; rate publication separately from a private push; and pair repository creation with
the push that populates it.

**Adjacent playbooks.** Whether a tag could be overwritten is
`../ecr.stealth.image-tag-overwrite-enabled/`. Whether the image was scanned is
`../ecr.stealth.image-scanning-disabled/`. Who pulled it afterwards is
`../ecr.collection.excessive-images-pulled/`. Who may pull it at all is
`../ecr.privilege-escalation.repository-policy-applied/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. ECR is **regional**, and `ecr-public` operates from
`us-east-1` — a single-region trail elsewhere sees neither the public registry nor repositories in
other regions.

**The list of roles that legitimately push images.** This is not a tuning refinement, it is the
entire discriminator: `PutImage` is what every deployment does. Without the list the rule is either
silent or constant.

**Image scanning enabled, and its findings retained.** The event says an image was registered; the
scan says what is in it. If scanning was disabled shortly before the push, that is itself the
earlier signal — see the adjacent playbook.

**Tag immutability on production repositories.** An immutable repository rejects a push to an
existing tag, which forces the technique onto a new tag and makes it far louder.

**Alerting (must be pre-configured)**

- **`PutImage` to `ecr-public.amazonaws.com` — publication outside the organisation, which deleting does not reverse → P0**
- **A repository created and populated by a non-deployment principal within the hour → P0**
- **`PutImage` from a principal not on the deployment-role allowlist → P0**

**Response Tooling**

An IAM principal that can call `ecr batch-delete-image`, `describe-images`,
`describe-image-scan-findings` and `put-image-tag-mutability` outside the change pipeline, in every
region holding repositories.

The ability to enumerate what is currently running each image digest — an ECS task list or a
Kubernetes workload query. The image is only dangerous where it is running.

**Known IOC Baselines**

The deployment roles, populating `known_provisioners`.

The list of repositories that are legitimately public. A push to the public registry outside that
list is unambiguous.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | `PutImage` against `ecr-public.amazonaws.com` outside the recorded public-repository list | CloudTrail | T1525 |
| P0 | `PutImage` from a principal not on the deployment-role allowlist | CloudTrail | T1525 |
| P0 | A repository created and an image pushed into it by the same principal within the hour | Correlation rule | T1525 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | Tag mutability changed on a repository shortly before a push — an existing tag becomes overwritable | CloudTrail | T1525 |
| P2 | `PutImage` from a deployment role at a time that does not match the release schedule | CloudTrail + change record | T1525 |
| P2 | `PutImage` to a repository with image scanning disabled | CloudTrail + repository config | T1525 |

### Detection Rule Quality Notes

Both source rules are threshold queries and fully readable, so every row below is auditable against
`_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `userIdentity.type:"iamuser"` — lowercase | CloudTrail emits `IAMUser`. On a case-sensitive field the rule matches nothing and **cannot fire**. Four other rules in the same ECR set spell it correctly | Removed entirely; the identity type is not the discriminator |
| Corrected, `IAMUser` still excludes `AssumedRole` | That is every CI/CD pipeline and every SSO session — the most likely route to this call | All identity types, with the deployment-role allowlist as the discriminator and `IdentityTypes` projected so the gap is measurable |
| Shipped as a building block with a threshold of 5 in 15 minutes | One malicious image is the incident, and a normal CI run pushes several tags for one build. Too high for the attack, too low for the pipeline | No volume dimension at all; the allowlist replaces it |
| Public and private registries rated identically | A private push is contained by deleting the image; a public one has already been distributed and may have been pulled by third parties | A dedicated rule for `ecr-public`, at high |
| Repository creation rated P4 and mapped to Implant Internal Image | An empty repository implants nothing. Rated as a finding it is noise; discarded it loses the lookalike-repository case | Informational base rule, plus a correlation with the push that populates it |
| Every rule in the ECR set excludes the same named human by ARN | A personal allowlist compiled into the detection logic for a whole service. Compromise that identity and all seven rules go blind together | A populated provisioner list a responder can read and change |
| `NOT "TLSv1.3"` on the repository rule | An unfielded term negation, discarding any event whose record contains that string — the TLS version of the call itself, which modern SDKs negotiate by default | Removed; it excludes attacker and administrator alike and has no reading under which it helps |
| MITRE: `T1578` on the push, `T1525` on the repository | ECR is a registry, not compute; and an empty repository is not an implanted image. The mappings are swapped in effect | `T1525` for the push, which is the technique it names |

**Recommended detection — the allowlist as discriminator, publication rated apart.**

```yaml
# Container image pushed to ECR by an unexpected principal (T1525)
#
# THE PUSH RULE CANNOT FIRE. It matches `userIdentity.type:"iamuser"`; CloudTrail emits `IAMUser`.
# On a case-sensitive field the lowercase form matches nothing. Four other rules in the same ECR set
# spell it correctly, so the pack writes one field two ways.
#
# AND EVEN CORRECTED, THE FILTER EXCLUDES THE NORMAL PUSH PATH. `userIdentity.type` of IAMUser
# excludes `AssumedRole`, which is what every CI/CD pipeline and every SSO session is. In a modern
# estate the pushes a detection most wants to see — from a build role — are exactly the ones the
# filter removes. All identity types are matched below; the discriminator is the ALLOWLIST, not the
# type.
#
# VOLUME IS THE WRONG SIGNAL FOR THIS TECHNIQUE. The source ships this as a building block with a
# threshold of five pushes in fifteen minutes. A single malicious image is the incident, and a normal
# CI run legitimately pushes several tags for one build (`latest`, a semver, a commit SHA), so the
# threshold is simultaneously too high to catch the attack and too low to avoid the pipeline.
#
# EVERY RULE IN THE ECR SET EXCLUDES THE SAME NAMED HUMAN BY ARN. That is a personal allowlist
# compiled into detection logic for a whole service: if that identity is compromised, all seven rules
# go blind together. Replaced here with a populated provisioner list a responder can read and change.
#
# THE REPOSITORY RULE CARRIES `NOT "TLSv1.3"`, AN UNFIELDED TERM NEGATION. It is not bound to a
# field, so it drops any event whose serialised record contains that string anywhere — which is the
# TLS version of the call itself. Modern SDKs negotiate TLS 1.3 by default, so the clause discards
# much of the traffic the rule exists to inspect, attacker and administrator alike.
#
# WHAT THE SOURCE GOT RIGHT: it matches `ecr-public.amazonaws.com` alongside the private registry.
# A push to the public registry distributes the image outside the account entirely, and it is a
# genuinely different outcome — so it ships here as its own rule rather than being folded in.
title: Container image pushed to ECR by a principal outside the deployment path
id: 3b7f04c1-98ae-4d52-a6f0-51c9e278b3da
name: ecr_image_pushed_by_unexpected_principal
status: experimental
description: >-
  A successful PutImage from a principal that is not a recorded deployment identity. One image is
  the incident — this is where a supply-chain implant enters, and everything downstream that pulls
  the tag runs it. All identity types are matched, because a compromised build role is the most
  likely route and it is an AssumedRole.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutImage.html
  - https://attack.mitre.org/techniques/T1525/
tags:
  - attack.persistence
  - attack.t1525
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecr.amazonaws.com'
    eventName: 'PutImage'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the roles that own image builds. This is the entire
  # discriminator — PutImage is what every deployment does.
  known_provisioners:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/ci-build'
  condition: selection and success and not known_provisioners
falsepositives:
  - >-
    A build role missing from the allowlist. That is the list being incomplete rather than the rule
    being wrong, and completing it is what makes this usable.
level: high
---
title: Container image pushed to the ECR Public registry
id: c6021ae7-4d38-49b1-83f5-70e6c4a19b2f
name: ecr_public_image_pushed
status: experimental
description: >-
  A successful PutImage against ecr-public.amazonaws.com. The public registry distributes the image
  outside the account and outside the organisation, so this is a different outcome from a private
  push — it is publication, and it is reachable by anyone. Shipped separately because the response
  differs: a private push is contained by deleting the image, a public one has already been
  distributed and may have been pulled by third parties.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutImage.html
  - https://attack.mitre.org/techniques/T1525/
tags:
  - attack.persistence
  - attack.exfiltration
  - attack.t1525
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecr-public.amazonaws.com'
    eventName: 'PutImage'
  success:
    errorCode: null
  condition: selection and success
falsepositives:
  - >-
    An organisation that genuinely publishes public images. It should be a short, recorded list of
    repositories, and a push to anything outside it is the finding.
level: high
---
title: ECR repository created and an image pushed to it by the same principal
id: 90e5cb43-1a76-42df-b508-3c7e061a94d8
status: experimental
description: >-
  A repository was created and an image pushed into it by the same principal within the hour. An
  empty repository implants nothing, which is why creating one is informational on its own — but a
  new repository appearing with an image in it is how a lookalike or typosquatted repository gets
  planted, and it is invisible to anything watching only established repositories.
references:
  - https://attack.mitre.org/techniques/T1525/
tags:
  - attack.persistence
  - attack.t1525
correlation:
  type: temporal_ordered
  rules:
    - ecr_repository_created
    - ecr_image_pushed
  group-by:
    - userIdentity.arn
  timespan: 1h
falsepositives:
  - >-
    A new service being onboarded, which legitimately creates a repository and pushes its first
    image. Allowlist the provisioning role on the base rules; the repository name is what a
    responder should read, since a lookalike is the whole point of the technique.
level: high
---
title: ECR repository created
id: 51fa9d02-6bc7-4e18-90a3-d825b6f04e17
name: ecr_repository_created
status: experimental
description: >-
  Base rule — correlation component and change accounting, never for direct alerting. A successful
  CreateRepository. A new repository is empty, so on its own it grants nothing and implants nothing;
  the source pack rates it P4 and maps it to Implant Internal Image, which an empty repository is
  not.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_CreateRepository.html
tags:
  - attack.persistence
  - attack.t1525
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecr.amazonaws.com'
    eventName: 'CreateRepository'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
title: Container image pushed to ECR
id: 7c48e6b0-2f91-4a35-b7d6-04e159a3c827
name: ecr_image_pushed
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. Any successful PutImage to
  either registry, including every ordinary build.
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

What this set structurally cannot do: say whether the image is malicious. `PutImage` registers a
manifest, not the layers. Scan findings and the digest are the evidence, and §2 Query 3 collects
them.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> ECR is **regional** and `ecr-public` operates from `us-east-1` — run these per region and include
> `us-east-1` even if you have no repositories there.

Run Query 1 first; it produces the repository, tag and digest the rest take as input.

#### Query 1 — Reconstruct: what was pushed, where, and by whom

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '30 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in PutImage CreateRepository PutImageTagMutability BatchDeleteImage; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      # The identity TYPE is printed because the source rule required IAMUser — and spelled it
      # lowercase, so it matched nothing. If every row here is AssumedRole, even the corrected rule
      # would never have fired.
      | (.userIdentity.type // "?") as $itype
      # ecr-public is a different registry with a different outcome: publication, not storage.
      | (if .eventSource == "ecr-public.amazonaws.com" then "PUBLIC-REGISTRY" else "private" end) as $reg
      | "\(.eventTime)  \(.eventName)  \($reg)  type=\($itype)  " +
        "repo=\(.requestParameters.repositoryName // "-")  tag=\(.requestParameters.imageTag // "-")  " +
        "by=\(.userIdentity.arn)  ip=\(.sourceIPAddress)"'
done | sort
```

A `CreateRepository` followed by a `PutImage` on the same repository is the lookalike shape — read
the repository **name** against your real ones. A `PUBLIC-REGISTRY` row is the most serious outcome
here regardless of who made it, because it cannot be reversed by deletion.

#### Query 2 — Which digest is live on the tag now

```bash
REPO="${1:?repository name from Query 1}"
TAG="${2:?image tag from Query 1}"
REGION="${AWS_REGION:-us-east-1}"

echo "=== What the tag points at right now ==="
aws ecr describe-images --repository-name "$REPO" --image-ids "imageTag=${TAG}" \
  --region "$REGION" --output json 2>/dev/null \
| jq -r '.imageDetails[] | "  digest=\(.imageDigest)",
         "  pushed=\(.imagePushedAt)  size=\(.imageSizeInBytes)",
         "  tags=\(.imageTags // [] | join(", "))"'

echo
echo "=== Is this repository immutable, and is it scanned? ==="
aws ecr describe-repositories --repository-names "$REPO" --region "$REGION" --output json 2>/dev/null \
| jq -r '.repositories[]
    | "  tagMutability: \(.imageTagMutability)",
      "  scanOnPush:    \(.imageScanningConfiguration.scanOnPush // false)",
      "  uri:           \(.repositoryUri)"'

echo
echo "[!] MUTABLE means the tag could have been repointed at a new digest with the old image still"
echo "    present — so a rollback is a re-tag rather than a redeploy. IMMUTABLE means the push had"
echo "    to use a NEW tag, which is louder and narrows what could have pulled it."
```

#### Query 3 — What is in the image, as far as anything can say

```bash
REPO="${1:?repository name}"
DIGEST="${2:?image digest from Query 2}"
REGION="${AWS_REGION:-us-east-1}"

echo "=== Scan findings, if the image was scanned ==="
aws ecr describe-image-scan-findings --repository-name "$REPO" \
  --image-id "imageDigest=${DIGEST}" --region "$REGION" --output json 2>/dev/null \
| jq -r 'if (.imageScanFindings.findingSeverityCounts // {}) == {} then
           "  (no findings recorded — the image may be unscanned, or scanning may have been disabled)"
         else (.imageScanFindings.findingSeverityCounts | to_entries[] | "  \(.key): \(.value)") end' \
  || echo "  [!] no scan findings available for this digest"

echo
echo "[!] An unscanned image is not a clean image. If scanning was disabled shortly before the push,"
echo "    that is the earlier signal — see ../ecr.stealth.image-scanning-disabled/."
echo "[!] Scan findings describe KNOWN CVEs in packages. They do not detect an implanted backdoor,"
echo "    which is what this technique plants. A clean scan is not exoneration."
```

The second warning is the important one. Vulnerability scanning answers a different question from
"was this image tampered with", and treating a clean scan as clearance is the most likely way this
incident gets closed early.

#### Query 4 — What has already pulled it

```bash
REPO="${1:?repository name}"
PUSH_TIME="${2:?push timestamp from Query 1}"
REGION="${AWS_REGION:-us-east-1}"

# BatchGetImage is called ONCE PER PULL to retrieve the manifest, so it is the right event for
# "who pulled this". It does NOT mean layers transferred — a client with the layers cached pulls
# the manifest and downloads nothing.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=BatchGetImage \
  --start-time "$PUSH_TIME" --region "$REGION" --output json 2>/dev/null \
| jq -r --arg r "$REPO" '.Events[].CloudTrailEvent | fromjson
    | select(.errorCode == null) | select(.requestParameters.repositoryName == $r)
    | "\(.eventTime)  pulled-by=\(.userIdentity.arn)  ip=\(.sourceIPAddress)"' | sort

echo
echo "[!] Every principal above ran, or is about to run, the image. Each is its own scope."
echo "    Node and task roles appear here as the AssumedRole session of the workload's role."
```

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The image is running wherever it has been pulled. Remove it from the registry first so nothing else
pulls it, then deal with what already did.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 1 shows a
`PUBLIC-REGISTRY` push, the image is already distributed outside your organisation. Delete it, but
record that deletion does not recall anything already pulled by a third party, and treat the content
of that image as disclosed.

#### Step 1 — Remove the image, preserving the digest first

```bash
REPO="${1:?repository name}"
DIGEST="${2:?image digest from Query 2}"
REGION="${AWS_REGION:-us-east-1}"

# The digest is the evidence — it is the only stable identifier once the tag is gone.
aws ecr describe-images --repository-name "$REPO" --image-ids "imageDigest=${DIGEST}" \
  --region "$REGION" --output json > "./evidence-${REPO//\//_}-${DIGEST##*:}.json" 2>/dev/null \
  && echo "[OK] image metadata preserved"

echo "[!] To analyse the image, pull it BEFORE deleting — after deletion the layers are gone:"
echo "    aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin ..."
echo "    docker pull <account>.dkr.ecr.${REGION}.amazonaws.com/${REPO}@${DIGEST}"

read -r -p "Delete image ${DIGEST} from ${REPO}? [y/N] " ANS
[ "$ANS" = "y" ] && aws ecr batch-delete-image --repository-name "$REPO" \
  --image-ids "imageDigest=${DIGEST}" --region "$REGION" \
  && echo "[OK] image deleted"
```

The prompt is deliberate: deleting the image destroys the only copy of what was pushed, and analysis
is frequently more valuable than the few minutes of exposure that deleting saves — particularly if
Step 2 has already stopped anything from pulling it.

#### Step 2 — Stop anything else pulling the tag

```bash
REPO="${1:?repository name}"
REGION="${AWS_REGION:-us-east-1}"

# Making the repository immutable does not remove the bad image, but it stops the tag being
# repointed again while you work.
aws ecr put-image-tag-mutability --repository-name "$REPO" \
  --image-tag-mutability IMMUTABLE --region "$REGION" \
  && echo "[OK] $REPO is now IMMUTABLE — tags cannot be repointed"

echo
echo "[!] If a known-good digest exists, re-tag it so consumers pulling the tag get the right image:"
echo "    aws ecr batch-get-image --repository-name $REPO --image-ids imageDigest=<good> \\"
echo "        --query 'images[0].imageManifest' --output text > /tmp/good.json"
echo "    aws ecr put-image --repository-name $REPO --image-tag <tag> \\"
echo "        --image-manifest file:///tmp/good.json --region $REGION"
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
    echo "[!] If $R is the BUILD role, revoking it stops all releases — and the compromise is"
    echo "    probably in the pipeline rather than in AWS. Treat the pipeline as in scope."
    ;;
  *) echo "[!] unrecognised principal shape: $PRINCIPAL — contain manually" ;;
esac
```

#### Step 4 — Deal with what already pulled it

Query 4 lists the principals that pulled the tag after the push. Each of those is running the image
now, and each is its own containment scope — an ECS task, an EKS pod, an EC2 node. Restarting them
against a corrected tag is the fix; leaving them running because the registry is clean is the error.

```bash
REGION="${AWS_REGION:-us-east-1}"
REPO_URI="${1:?repository URI from Query 2}"

echo "=== ECS tasks running this image ==="
for CLUSTER in $(aws ecs list-clusters --region "$REGION" --query 'clusterArns[]' --output text 2>/dev/null); do
  aws ecs list-tasks --cluster "$CLUSTER" --region "$REGION" --query 'taskArns[]' --output text 2>/dev/null \
  | tr '\t' '\n' | while read -r T; do
      [ -z "$T" ] && continue
      aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$T" --region "$REGION" --output json 2>/dev/null \
      | jq -r --arg u "$REPO_URI" --arg c "$CLUSTER" \
          '.tasks[].containers[] | select(.image | startswith($u)) | "  \($c)  \(.image)"'
    done
done
echo "[!] EKS workloads are not listed here — query them with kubectl against the same image URI."
```

---

## 4. Eradication

### Remove Attacker Access

#### Treat a clean vulnerability scan as irrelevant, not reassuring

Scanning finds known CVEs in packages. It does not detect an implanted backdoor, which is what this
technique plants. The most likely way this incident gets closed early is a clean scan being read as
clearance, and the eradication decision should rest on the image's provenance — was it built by the
pipeline, from a known commit — rather than on its scan result.

#### Make production repositories immutable

An immutable repository rejects a push to an existing tag. That does not stop an image being pushed,
but it forces the technique onto a **new** tag, which nothing is configured to pull and which is far
more visible. It is the cheapest structural change here.

#### Restrict who may push, and separate it from who may pull

`ecr:PutImage` and `ecr:InitiateLayerUpload` belong to the build pipeline. Workload roles need
`ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer` and nothing more. Where a workload role can also
push, a compromised workload can implant into the registry it pulls from.

#### Deny pushing outside the build path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyImagePushOutsideBuildPath",
  "Effect": "Deny",
  "Action": ["ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
             "ecr:CompleteLayerUpload", "ecr-public:PutImage"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourBuildRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone including the pipeline. The layer-upload actions are included deliberately: denying
`PutImage` alone still allows layers to be staged. Test in a non-production OU first.

---

## 5. Recovery

### Restore Clean State

#### Verify the tag points at a known-good digest

```bash
REPO="${1:?repository name}"
TAG="${2:?image tag}"
EXPECT_DIGEST="${3:?the digest the build pipeline produced}"
REGION="${AWS_REGION:-us-east-1}"

CUR="$(aws ecr describe-images --repository-name "$REPO" --image-ids "imageTag=${TAG}" \
        --region "$REGION" --query 'imageDetails[0].imageDigest' --output text 2>/dev/null)"
if [ "$CUR" = "$EXPECT_DIGEST" ]; then
  echo "[OK] $REPO:$TAG points at the expected digest"
else
  echo "[FAIL] $REPO:$TAG is $CUR, expected $EXPECT_DIGEST"
fi
```

The expected digest must come from the **build pipeline**, not from the registry. A digest read from
the registry describes what is there, which is the thing under suspicion.

#### Verify the bad digest is gone and the repository is immutable

```bash
REPO="${1:?repository name}"
BAD_DIGEST="${2:?the pushed digest}"
REGION="${AWS_REGION:-us-east-1}"

if aws ecr describe-images --repository-name "$REPO" --image-ids "imageDigest=${BAD_DIGEST}" \
     --region "$REGION" >/dev/null 2>&1; then
  echo "[FAIL] $BAD_DIGEST is still present in $REPO"
else
  echo "[OK] $BAD_DIGEST removed from $REPO"
fi

aws ecr describe-repositories --repository-names "$REPO" --region "$REGION" \
  --query 'repositories[0].imageTagMutability' --output text 2>/dev/null \
| while read -r M; do
    [ "$M" = "IMMUTABLE" ] && echo "[OK] $REPO is IMMUTABLE" \
                           || echo "[FAIL] $REPO is $M — tags can still be repointed"
  done
```

#### Verify nothing is still running the image

```bash
REPO_URI="${1:?repository URI}"
BAD_DIGEST="${2:?the pushed digest}"
REGION="${AWS_REGION:-us-east-1}"

FOUND=0
for CLUSTER in $(aws ecs list-clusters --region "$REGION" --query 'clusterArns[]' --output text 2>/dev/null); do
  aws ecs list-tasks --cluster "$CLUSTER" --region "$REGION" --query 'taskArns[]' --output text 2>/dev/null \
  | tr '\t' '\n' | while read -r T; do
      [ -z "$T" ] && continue
      aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$T" --region "$REGION" --output json 2>/dev/null \
      | jq -r --arg d "$BAD_DIGEST" --arg c "$CLUSTER" \
          '.tasks[].containers[] | select((.imageDigest // "") == $d) | "[FAIL] \($c) still running the pushed digest"'
    done
done
echo "[!] Check EKS separately — this only covers ECS. A pod restarted from a cached image on a node"
echo "    keeps running it until the node is drained or the image is evicted."
```

#### Confirm the corrected detection fires

```bash
REPO="${1:?a NON-PRODUCTION repository name}"
REGION="${AWS_REGION:-us-east-1}"

# Re-push the repository's OWN current manifest under a throwaway tag. The image is byte-identical,
# so nothing changes, but PutImage is emitted — and it must fire from an AssumedRole session, which
# is exactly the identity type the source rule excluded.
DIGEST="$(aws ecr describe-images --repository-name "$REPO" --region "$REGION" \
           --query 'sort_by(imageDetails,&imagePushedAt)[-1].imageDigest' --output text 2>/dev/null)"
aws ecr batch-get-image --repository-name "$REPO" --image-ids "imageDigest=${DIGEST}" \
  --region "$REGION" --query 'images[0].imageManifest' --output text > /tmp/manifest.json 2>/dev/null

aws ecr put-image --repository-name "$REPO" --image-tag "detection-test" \
  --image-manifest "file:///tmp/manifest.json" --region "$REGION" >/dev/null 2>&1 \
  && echo "[OK] identical manifest pushed under a test tag — expect the HIGH rule within 15 min"

aws sts get-caller-identity --query Arn --output text
echo "[!] If that ARN contains ':assumed-role/' and no alert arrives, the identity filter is still"
echo "    in place and the rule covers none of your real builds."

sleep 60
aws ecr batch-delete-image --repository-name "$REPO" --image-ids "imageTag=detection-test" \
  --region "$REGION" >/dev/null 2>&1 && echo "[OK] test tag removed"
rm -f /tmp/manifest.json
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| What identity type made the push? | If `AssumedRole`, the source rule could never have fired — the coverage gap is the finding, not the push. |
| Was the caller the build role? | If yes, the compromise is upstream in the pipeline and AWS containment alone does not address it. |
| Was it the public registry? | Publication cannot be reversed by deletion, and the content should be treated as disclosed. |
| Was the repository mutable? | Decides whether an existing tag was repointed or a new tag was introduced, and therefore what could have pulled it. |
| Was the image scanned, and was a clean scan treated as clearance? | Scanning finds CVEs, not implants. If the incident was closed on a clean scan, the process failed. |
| What pulled the tag after the push? | Every one of those is running the image, and the registry being clean does not change that. |

### Recommended Guardrails

**Make the deployment-role allowlist the discriminator.** Identity type does not work — the majority
of real pushes are `AssumedRole` — and volume does not work, because one image is the incident.

**Make production repositories immutable.** It forces the technique onto a new tag, which nothing is
configured to pull.

**Separate push permission from pull permission.** A workload role that can also push can implant
into the registry it pulls from.

**Do not treat a clean vulnerability scan as clearance.** It answers a different question from
"was this tampered with", and the difference is the whole technique.

**Cover the public registry explicitly.** It is a different outcome with a different response, and
most rule sets omit it entirely — the source pack included it, which is the one thing it got right
here.

### Technique Reference

**T1525 — Implant Internal Image.** Verified live at https://attack.mitre.org/techniques/T1525/ on
2026-08-30. Pushing a malicious image into a registry that workloads pull from is precisely what this
technique names.

The source pack maps the **push** to `T1578 — Modify Cloud Compute Infrastructure` — ECR is a
registry, not compute — and maps **repository creation** to `T1525`, which an empty repository is
not. The two mappings are effectively swapped.

AWS references relied on throughout, all verified 2026-08-30:

- `PutImage`: https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutImage.html
- `BatchGetImage` — one call per pull, manifest only:
  https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_BatchGetImage.html

Service-wide verified behaviour shared by every `ecr.*` playbook is in `../_ground-truth/ecr.md`.

### Residual Risk

**A compromised build role defeats the allowlist by construction.** The discriminator is "was the
caller a deployment identity", and if the pipeline itself is compromised the answer is yes. Image
signing and pipeline integrity are the controls for that; nothing in CloudTrail distinguishes a
legitimate build from a malicious one made by the same role.

**Deleting a public image does not un-distribute it.** Anything that pulled it during the exposure
window has it, and that population is outside your account and unenumerable.

**A cached image survives registry deletion.** A node that already pulled the layers keeps running
the image until it is drained or the image is evicted. Registry state and running state are different
questions.

**Scan findings are not integrity evidence.** An implanted backdoor in an otherwise current base
image produces no CVE findings at all, so a clean scan is consistent with a fully compromised image.
