# IR Playbook: ECR Images Pulled at Breadth — registry walk via `ecr:BatchGetImage`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Collection — container images are pulled across many repositories, taking whatever they contain out of the registry |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High when pulls span five or more distinct repositories, or follow registry enumeration; medium for a pull by a principal outside the workload and build roles. The source rule ships as a building block — not rated at all. |
| MITRE Tactics | Collection |
| MITRE Techniques | T1530 |
| Services in Scope | ECR, ECR Public, ECS, EKS, CloudTrail |

**What the technique does:** the actor pulls images. Whatever is baked into them comes out —
embedded credentials, configuration, proprietary code, internal hostnames. Unlike a push, the act is
complete on the first call and containment cannot undo it.

**Why the usual reflexes miss it.** The first is the identity filter: the source rule matches
`userIdentity.type:"iamuser"` — lowercase, so it cannot fire, and corrected it would exclude
`AssumedRole`, which is what performs essentially every pull. This is the unusual case where the
filter is useless in both spellings. The second is counting pulls: ten in fifteen minutes is a node
starting up, all from one repository, while ten across ten repositories is a registry walk — and a
flat threshold cannot separate them. The third is reading pull count as bytes transferred; a client
with cached layers pulls the manifest and downloads nothing. The fourth is treating deletion as
containment, when the content has already left.

**Detection thesis:** count **distinct repositories** rather than pulls, keep the manifest call and
the layer call separate because they answer different questions, and treat enumeration-then-pull as
the highest-confidence shape.

**Adjacent playbooks.** The opposite direction — an image pushed into the registry — is
`../ecr.stealth.malicious-image-pushed/`. Who is permitted to pull at all is
`../ecr.privilege-escalation.repository-policy-applied/`.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**

CloudTrail management events in every region. ECR is **regional** and `ecr-public` operates from
`us-east-1`, so a single-region trail sees neither the public registry nor repositories elsewhere.

**A record of what your images contain that would matter if disclosed.** This is the prerequisite
that shapes the whole response: containment here is rotation, and rotating requires knowing what is
baked in. An estate that cannot answer "what credentials are in this image" cannot scope this
incident at all.

The list of workload and build roles that legitimately pull. It is long in a large estate — one per
task role — which is why the breadth correlation, which needs no such list, carries the severity.

**Alerting (must be pre-configured)**

- **Registry enumerated (`DescribeRepositories` / `ListImages`) and then images pulled from five or more repositories by the same principal → P0**
- **Images pulled from five or more distinct repositories within fifteen minutes by a principal that is not a workload or build role → P0**
- **`BatchGetImage` by a principal outside the workload and build roles → P2**

**Response Tooling**

Read access to CloudTrail across the relevant window and the ability to enumerate what each image
contains — a build manifest, an SBOM, or the Dockerfile.

The credential inventory for anything baked into images, so rotation can start immediately rather
than after an archaeology exercise.

**Known IOC Baselines**

The workload and build roles, populating `known_pullers`.

Normal pull breadth per principal. A build agent that legitimately pulls base images from many
repositories looks exactly like the technique, and the only way to tell is knowing it does.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P0 | Repositories or images enumerated, then pulls across five or more repositories by the same principal | Correlation + CloudTrail | T1530 |
| P0 | Pulls across five or more distinct repositories in fifteen minutes by a principal that is not a workload or build role | Correlation rule | T1530 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|----------------|--------|-------|
| P2 | Pulls across five or more distinct repositories in fifteen minutes by any principal | Correlation rule | T1530 |
| P2 | `BatchGetImage` by a principal outside the workload and build roles | CloudTrail | T1530 |
| P2 | High pull count with near-zero `GetDownloadUrlForLayer` — a fleet restarting on cached layers, and explicitly *not* content leaving | CloudTrail | T1530 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| `userIdentity.type:"iamuser"` — lowercase | CloudTrail emits `IAMUser`. On a case-sensitive field the rule matches nothing and **cannot fire** | Removed |
| Corrected, `IAMUser` still excludes `AssumedRole` | Image pulls are performed almost entirely by roles — task roles, node roles, CI runners. This is the unusual case where the filter is useless in **both** spellings | A puller allowlist for the low-severity rule, and a breadth correlation that needs no list for the high one |
| Counts pulls, threshold 10 in 15 minutes | A node starting up or a deployment rolling out produces exactly that, from one or two repositories. A registry walk produces fewer pulls across many more repositories | A `value_count` correlation on **distinct `repositoryName`**, which separates the two without tuning |
| Treats `BatchGetImage` as data movement | AWS documents it as one call per pull returning the **manifest**. Layer bytes come from `GetDownloadUrlForLayer`, and a cached client downloads nothing | Both calls shipped as separate base rules, with the query reporting them side by side |
| No coverage of `GetDownloadUrlForLayer` or enumeration | The layer call is where content transfers; enumeration is what precedes a walk. Neither is in the source pack | Both added — the layer call as a base rule, enumeration surfaced in the query's verdicts |
| Shipped as a building block, so never rated | An unrated rule produces no output at all | High for breadth, medium for an unexpected puller |
| Excludes the same named human as every other ECR rule | A personal allowlist compiled into detection logic for a whole service | A populated puller list a responder can read and change |

**Recommended detection — breadth as the signal, with the two call types kept apart.**

```yaml
# Container images pulled from ECR at breadth (T1530)
#
# THE RULE CANNOT FIRE, AND CORRECTING IT BARELY HELPS. It matches
# `userIdentity.type:"iamuser"` — CloudTrail emits `IAMUser`, so on a case-sensitive field it
# matches nothing. Corrected, it still excludes `AssumedRole`, and image pulls are almost entirely
# AssumedRole: every ECS task role, every EKS node role, every CI runner. The identity type is not a
# useful discriminator for this operation in either spelling.
#
# `BatchGetImage` COUNTS PULLS BUT DOES NOT MEAN CONTENT MOVED. AWS: "When an image is pulled, the
# BatchGetImage API is called once to retrieve the image manifest." So it is a fair proxy for pull
# COUNT — better than it first looks — but its response carries `imageManifest` only. The layer
# bytes come from `GetDownloadUrlForLayer`, and a client that already has the layers cached pulls
# the manifest and downloads nothing. Where the question is exfiltration, the layer call is the one
# that corresponds to data movement, and the source rule does not watch it.
#
# VOLUME IS THE WRONG AXIS; BREADTH IS THE RIGHT ONE. Ten pulls in fifteen minutes is an ordinary
# node starting up or a deployment rolling out — all from ONE or TWO repositories. Ten pulls across
# ten DIFFERENT repositories by one principal is someone walking the registry. The source rule
# counts pulls and cannot tell those apart; the correlation below counts distinct repositories.
#
# AND IT EXCLUDES THE SAME NAMED HUMAN AS EVERY OTHER RULE IN THE ECR SET, by ARN, inline. See
# ../../_ground-truth/ecr.md §3.
title: ECR images pulled across many repositories by one principal
id: 4c8e17b3-52da-4f09-a761-e3805db2c46f
status: experimental
description: >-
  One principal pulled images from five or more distinct repositories within fifteen minutes.
  Breadth is the signal, not volume: a node starting up or a deployment rolling out produces many
  pulls from one or two repositories, while walking the registry produces few pulls from many. The
  source rule counts pulls and cannot separate the two.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_BatchGetImage.html
  - https://attack.mitre.org/techniques/T1530/
tags:
  - attack.collection
  - attack.t1530
correlation:
  type: value_count
  rules:
    - ecr_image_pulled
  group-by:
    - userIdentity.arn
  timespan: 15m
  condition:
    gte: 5
    field: requestParameters.repositoryName
falsepositives:
  - >-
    A build agent that pulls base images from many repositories, or a mirroring job. Both are real
    and both should be allowlisted by role on the base rule — the threshold cannot distinguish them
    because they are behaviourally identical to the technique.
level: high
---
title: ECR image pulled by a principal outside the workload and build roles
id: 9a02f7e5-6c31-4b48-80d7-152ea94c6b03
name: ecr_pull_by_unexpected_principal
status: experimental
description: >-
  A successful BatchGetImage from a principal that is neither a workload role nor a build role.
  Pulling an image is how its contents leave the registry, and a human or a standalone IAM user
  doing it is not how images normally reach anything. Rated medium rather than high because a single
  pull has ordinary explanations — an engineer debugging — and the breadth correlation carries the
  severity.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_BatchGetImage.html
  - https://attack.mitre.org/techniques/T1530/
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource:
      - 'ecr.amazonaws.com'
      - 'ecr-public.amazonaws.com'
    eventName: 'BatchGetImage'
  success:
    errorCode: null
  # POPULATE BEFORE DEPLOYING with the workload and build roles that legitimately pull. Deployed
  # empty this fires on every container start in the estate.
  known_pullers:
    userIdentity.arn|contains:
      - ':role/PlatformAutomation'
      - ':role/ci-build'
      - ':role/ecsTaskExecutionRole'
      - ':role/eks-node'
  condition: selection and success and not known_pullers
falsepositives:
  - >-
    A workload role missing from the list. In an estate with many task roles this list is long and
    keeping it current is the maintenance cost of this rule — which is why the breadth correlation,
    which needs no such list, is the one rated high.
level: medium
---
title: ECR image layers downloaded
id: 7f31d5a0-84b6-4e27-9c50-a6e0138b2f4d
name: ecr_layer_download_issued
status: experimental
description: >-
  Base rule — correlation component and change accounting, never for direct alerting. A successful
  GetDownloadUrlForLayer. This is the call that corresponds to image content actually transferring,
  unlike BatchGetImage which returns only the manifest. It fires many times per pull, once per
  layer, so its volume is not comparable to a pull count.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_GetDownloadUrlForLayer.html
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource:
      - 'ecr.amazonaws.com'
      - 'ecr-public.amazonaws.com'
    eventName: 'GetDownloadUrlForLayer'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
title: ECR image pulled
id: b5720ce8-1e49-4a63-95f1-08d3ea6b71c9
name: ecr_image_pulled
status: experimental
description: >-
  Base rule — correlation component only, never for direct alerting. A successful BatchGetImage,
  which AWS documents as being called once per pull to retrieve the manifest. Every container start
  in the estate produces one.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_BatchGetImage.html
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource:
      - 'ecr.amazonaws.com'
      - 'ecr-public.amazonaws.com'
    eventName: 'BatchGetImage'
  success:
    errorCode: null
  condition: selection and success
level: informational
```

What this set structurally cannot do: say what was inside the images. That is a build-artefact
question, answered from an SBOM or a Dockerfile, and it is the question the whole response depends
on.

### Key Investigation Queries

> **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your
> log platform for busy windows. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`.
> ECR is **regional** and `ecr-public` operates from `us-east-1` — run these per region.

Run Query 1 first; it establishes breadth, which is what decides whether this is a rollout or a walk.

#### Query 1 — Reconstruct: breadth, and whether enumeration preceded it

```bash
REGION="${AWS_REGION:-us-east-1}"
START="$(date -u -v-7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -d '7 days ago' '+%Y-%m-%dT%H:%M:%SZ')"

for EVT in BatchGetImage GetDownloadUrlForLayer DescribeRepositories ListImages; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EVT" \
    --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r '.Events[].CloudTrailEvent | fromjson
      | select(.errorCode == null)
      # BatchGetImage is one call per PULL and returns the manifest only.
      # GetDownloadUrlForLayer is where content actually transfers — many per pull, one per layer.
      | (if .eventName == "BatchGetImage" then "PULL"
         elif .eventName == "GetDownloadUrlForLayer" then "layer"
         else "ENUMERATE" end) as $kind
      | "\(.eventTime)  \($kind)  \(.userIdentity.arn)  " +
        "repo=\(.requestParameters.repositoryName // "-")  type=\(.userIdentity.type // "?")"'
done | sort
```

Count **distinct repositories** per principal, not rows. Five or more in a fifteen-minute window is
the finding; forty pulls from one repository is a deployment. An `ENUMERATE` line before the pulls is
the strongest shape here — a workload pulls the image it was configured with and does not look
around first.

#### Query 2 — Did content actually transfer, or was it cached

```bash
PRINCIPAL="${1:?principal ARN from Query 1}"
REGION="${AWS_REGION:-us-east-1}"
START="${2:?window start from Query 1}"

case "$PRINCIPAL" in
  *:assumed-role/*) LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $2}')" ;;
  *)                LOOKUP="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')" ;;
esac

PULLS=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=BatchGetImage \
  --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r --arg u "$LOOKUP" '[.Events[] | select(.Username == $u)] | length')
LAYERS=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetDownloadUrlForLayer \
  --start-time "$START" --region "$REGION" --output json 2>/dev/null \
  | jq -r --arg u "$LOOKUP" '[.Events[] | select(.Username == $u)] | length')

echo "pulls (manifests): ${PULLS:-0}"
echo "layer fetches:     ${LAYERS:-0}"
if [ "${PULLS:-0}" -gt 0 ] && [ "${LAYERS:-0}" -eq 0 ]; then
  echo "[!] Manifests retrieved but NO layers fetched. Either the client already had every layer"
  echo "    cached, or it was checking which tags exist rather than pulling. Content did not move."
elif [ "${LAYERS:-0}" -gt 0 ]; then
  echo "[!] Layers were fetched — image content transferred. Scope the response to what those"
  echo "    images contain, not to the registry."
fi
```

This is the query that decides how serious the incident is, and the answer is frequently "content
did not move". A high pull count on a restarting fleet is normal and produces no layer fetches at
all.

#### Query 3 — What was in the images

```bash
REPO="${1:?repository name from Query 1}"
REGION="${AWS_REGION:-us-east-1}"

aws ecr describe-images --repository-name "$REPO" --region "$REGION" \
  --query 'sort_by(imageDetails,&imagePushedAt)[-3:].[imageTags[0],imageDigest,imagePushedAt]' \
  --output text 2>/dev/null | sed 's/^/  /'

cat <<'NOTE'

[!] The registry cannot tell you what is inside. Answer this from the build side:
      - the SBOM or build manifest for the digest, if you produce one
      - the Dockerfile and its build args
      - any secret-scanning result for the image layers
    What matters is whether the image carries credentials, tokens, internal endpoints or
    proprietary code. That list is the scope of the incident, and it is the reason
    containment here is ROTATION rather than deletion.
NOTE
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

`GetAuthorizationToken` before the pulls is how a client authenticates to the registry — its presence
is unremarkable, but its **source address** is not, and it is the event that ties a `docker login` to
everything that followed.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

The pull has already happened. Nothing you do to the registry undoes it, so containment is about the
credential and about what the images contained — in that order.

**Break-glass — use the break-glass credential, not the on-call's own.** If Query 2 shows layer
fetches across many repositories, image content has left. Start rotation of anything baked into
those images before completing the investigation; the rotation is the long pole and it does not
depend on knowing exactly who did it.

#### Step 1 — Revoke the credential that pulled

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
    echo "[!] If $R is a WORKLOAD role, this stops the workload. On a task or node role that is an"
    echo "    outage — weigh it against what the images contained."
    ;;
  *) echo "[!] unrecognised principal shape: $PRINCIPAL — contain manually" ;;
esac
```

#### Step 2 — Rotate what the images contained

```bash
cat <<'NOTE'
[!] This is the containment action for this technique. Work Query 3's list.

    For every repository pulled, rotate anything the image carries:
      - credentials or tokens baked into layers or ENV
      - private keys, certificates, signing material
      - internal endpoints and hostnames — these cannot be rotated, so record them as disclosed

    Deleting the image, revoking the puller and making the repository private all change what
    happens NEXT. None of them affects what has already left, and treating them as containment is
    the most common error in this incident type.
NOTE

REPO="${1:?repository name}"
REGION="${AWS_REGION:-us-east-1}"
echo "=== who else can pull this repository, and should they ==="
aws ecr get-repository-policy --repository-name "$REPO" --region "$REGION" \
  --query 'policyText' --output text 2>/dev/null \
| jq -r '(if (.Statement | type) == "object" then [.Statement] else .Statement end)[]
    | select(.Effect == "Allow")
    | "  \(.Principal)  actions=\(.Action)"' \
  || echo "  (no repository policy — access is governed by IAM identity policies only)"
```

#### Step 3 — Narrow who may pull

```bash
REPO="${1:?repository name}"
REGION="${AWS_REGION:-us-east-1}"

echo "[!] A repository policy is the resource-side control. Removing a broad Allow here is faster"
echo "    than auditing every identity policy that might grant ecr:BatchGetImage."
echo "    The policy structure and its pitfalls are owned by"
echo "    ../ecr.privilege-escalation.repository-policy-applied/ — use its Step 2 to edit safely."

aws ecr describe-repositories --repository-names "$REPO" --region "$REGION" \
  --query 'repositories[0].[repositoryName,repositoryUri]' --output text 2>/dev/null | sed 's/^/  /'
```

#### Step 4 — Decide whether this was a walk or a rollout, and close accordingly

Query 1's distinct-repository count and Query 2's layer-fetch count together answer this, and the
three outcomes have genuinely different endings:

- **Many repositories, layers fetched** — a registry walk with content transfer. Rotation, and treat
  the image contents as disclosed.
- **Many repositories, no layers** — manifests retrieved and nothing downloaded. Still worth
  explaining, because a workload does not enumerate, but nothing left.
- **One or two repositories, many pulls** — a deployment or a restarting fleet. Close it, and add the
  role to `known_pullers` so it does not recur.

---

## 4. Eradication

### Remove Attacker Access

#### Rotate first, and record what cannot be rotated

Credentials in images can be rotated. Internal hostnames, architecture and proprietary code cannot.
The eradication record should separate the two explicitly, because the second list is what carries
forward into risk acceptance rather than remediation.

#### Stop baking secrets into images

This is the durable fix and it is the only one that reduces the impact of the next occurrence.
Images should take secrets at runtime from Secrets Manager or SSM Parameter Store, so that pulling
an image yields nothing worth having.

#### Separate pull permission from push permission, and scope it per repository

A workload needs `ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer` on **its own** repository.
Estate-wide pull permission on `Resource: "*"` is what turns one compromised task role into a
registry walk, and it is extremely common because it is the path of least resistance when writing
the first task definition.

#### Deny registry enumeration outside the build path

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Sid": "DenyRegistryEnumerationOutsideBuild",
  "Effect": "Deny",
  "Action": ["ecr:DescribeRepositories", "ecr:ListImages"],
  "Resource": "*",
  "Condition": {
    "ArnNotLike": {"aws:PrincipalARN": ["arn:aws:iam::*:role/YourBuildRole",
                                        "arn:aws:iam::*:role/YourBreakGlassRole"]}
  }
}
```

Attach it to an OU, not the management account, where SCPs do not apply. Both role names must be
roles that genuinely exist — an `ArnNotLike` against a non-existent role denies the action to
everyone including the pipeline. Note this denies **enumeration**, not pulling: a workload does not
need to list repositories to pull the image it was configured with, so this is unusually cheap and it
removes the reconnaissance half of the technique.

---

## 5. Recovery

### Restore Clean State

#### Verify the puller's access is actually gone

```bash
PRINCIPAL="${1:?principal ARN}"
REPO="${2:?repository name}"
REGION="${AWS_REGION:-us-east-1}"

case "$PRINCIPAL" in
  *:user/*)
    U="$(printf '%s' "$PRINCIPAL" | awk -F'/' '{print $NF}')"
    ACTIVE="$(aws iam list-access-keys --user-name "$U" \
               --query 'length(AccessKeyMetadata[?Status==`Active`])' --output text 2>/dev/null)"
    [ "${ACTIVE:-0}" -eq 0 ] && echo "[OK] no active access keys for $U" \
                             || echo "[FAIL] $U still has $ACTIVE active key(s)"
    ;;
  *:assumed-role/*)
    R="$(printf '%s' "$PRINCIPAL" | awk -F'assumed-role/' '{print $2}' | awk -F'/' '{print $1}')"
    aws iam list-role-policies --role-name "$R" --query 'PolicyNames' --output text 2>/dev/null \
    | tr '\t' '\n' | grep -q 'RevokeOlderSessions' \
      && echo "[OK] session revocation policy attached to $R" \
      || echo "[FAIL] no RevokeOlderSessions policy — sessions issued before containment are valid"
    ;;
esac
```

#### Verify rotation completed for what the images carried

```bash
cat <<'NOTE'
[!] There is no AWS API that answers this. Confirm against the list from §3 Step 2:

      [ ] every credential baked into a pulled image has been rotated
      [ ] every token or key has been revoked at its issuer, not just replaced in the image
      [ ] what could not be rotated (hostnames, architecture, source) is recorded as disclosed
      [ ] the rebuilt images no longer contain the rotated material

    The last box is the one most often missed: rotating a secret and rebuilding from a Dockerfile
    that still bakes one in returns the estate to the same state with a different value.
NOTE
```

#### Confirm the corrected detection fires

```bash
REGION="${AWS_REGION:-us-east-1}"

# Exercise BREADTH, which is the routable signal — pulling many times from ONE repository must NOT
# fire, and pulling once from several must. Manifest reads only; nothing is downloaded.
REPOS=$(aws ecr describe-repositories --region "$REGION" \
         --query 'repositories[0:5].repositoryName' --output text 2>/dev/null)
COUNT=0
for R in $REPOS; do
  D=$(aws ecr describe-images --repository-name "$R" --region "$REGION" \
       --query 'sort_by(imageDetails,&imagePushedAt)[-1].imageDigest' --output text 2>/dev/null)
  [ -z "$D" ] || [ "$D" = "None" ] && continue
  aws ecr batch-get-image --repository-name "$R" --image-ids "imageDigest=${D}" \
    --region "$REGION" >/dev/null 2>&1 && COUNT=$((COUNT + 1))
done
echo "[OK] manifests read from $COUNT distinct repositories — expect the breadth correlation"
echo "[!] No layers were fetched, so this test moves no content. If the alert fires on pull COUNT"
echo "    rather than repository BREADTH, the correlation is not the one deployed."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Question | Why it matters here |
|----------|---------------------|
| How many distinct repositories, versus how many pulls? | This is the whole triage. Forty pulls from one repository is a deployment; five pulls from five repositories is a walk. |
| Were layers fetched, or only manifests? | Decides whether content left or a fleet restarted on cached images. |
| Did enumeration precede the pulls? | A workload pulls what it was configured with and does not look around first. |
| What did the images contain? | This is the scope of the incident, and no AWS API answers it — it comes from the build side. |
| Did the puller hold `ecr:BatchGetImage` on `Resource: "*"`? | Estate-wide pull permission is what turns one compromised role into a registry walk. |
| Was containment rotation, or deletion? | Deleting the image changes nothing about what already left. |

### Recommended Guardrails

**Count repositories, not pulls.** It is the one change that makes this detectable without tuning,
because a rollout and a walk differ in breadth and not in volume.

**Stop baking secrets into images.** It is the only measure that reduces the impact rather than the
likelihood, and it makes a successful pull worth nothing.

**Scope pull permission per repository.** A task role needs its own image and no others.

**Deny registry enumeration outside the build path.** A workload never needs to list repositories,
so this is close to free and removes the reconnaissance half of the technique.

**Do not rely on identity type.** Pulls are performed by roles by design. Any rule filtering on
`IAMUser` — however it is spelled — sees essentially nothing.

### Technique Reference

**T1530 — Data from Cloud Storage.** Verified live at https://attack.mitre.org/techniques/T1530/ on
2026-08-30. This is the source rule's own mapping and it is correct: a container image is stored
data, and pulling it is how the contents leave.

AWS references relied on throughout, all verified 2026-08-30:

- `BatchGetImage` — one call per pull, returning the manifest only:
  https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_BatchGetImage.html
- `GetDownloadUrlForLayer` — the call that corresponds to content transferring:
  https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_GetDownloadUrlForLayer.html

Service-wide verified behaviour shared by every `ecr.*` playbook is in `../_ground-truth/ecr.md`.

### Residual Risk

**The pull cannot be undone.** Every other playbook in this set has a containment action that stops
the technique. This one does not — the content left at the moment of the call, and rotation is
recovery rather than containment.

**Layer counts do not tell you volume in bytes.** `GetDownloadUrlForLayer` issues a URL; the transfer
happens against S3 and is not in CloudTrail as an ECR event. A large layer and a small one produce
one call each.

**A legitimate build agent is behaviourally identical.** An agent pulling base images from many
repositories produces exactly the pattern the correlation detects. Only the `known_pullers` list
separates them, and an estate that has not built that list will close this alert as a build job every
time — including when it is not one.

**What the images contain is outside AWS entirely.** The scope of this incident is determined by
build artefacts, and an estate without an SBOM or a reliable Dockerfile history cannot establish it
from anything AWS holds.
