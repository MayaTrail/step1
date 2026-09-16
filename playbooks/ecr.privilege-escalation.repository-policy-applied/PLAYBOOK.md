# IR Playbook: ECR Repository Policy Rewritten — Push Access Granted via `ecr:SetRepositoryPolicy`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Account manipulation (a container registry's resource policy is replaced, granting push or pull to a principal that should not have it) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | High. A push grant on a repository whose images run in production is arbitrary code execution on a delay: the next deployment pulls whatever is under the tag. `SetRepositoryPolicy` **replaces** the whole policy, so a single call can also silently remove every existing restriction. The source rule rates it P3 and cannot distinguish a grant from a tightening. |
| MITRE Tactics | Persistence, Privilege Escalation |
| MITRE Techniques | T1098 |
| Services in Scope | ECR, IAM, ECS/EKS or whatever runs the images, CloudTrail |

**What the technique does:** the actor calls `ecr:SetRepositoryPolicy` with a policy document
granting `ecr:PutImage`, `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart` and
`ecr:CompleteLayerUpload` to a principal they control — often an external account ID, sometimes
`"AWS": "*"`. Nothing else changes. The repository keeps its name, its existing images and its
lifecycle policy. At the next deployment the orchestrator pulls the tag and runs whatever is now
behind it.

**Why the usual reflexes miss it.** The call is indistinguishable by name from the one that
*tightens* a policy — `SetRepositoryPolicy` is the only write verb ECR has for this, and it
**replaces** rather than merges, so removing every restriction and adding a legitimate reader are
the same event with the same success. A defender watching event names sees an estate that changes
repository policies routinely and mutes the rule. The second reflex, checking for a new image, is
too late: the grant is the incident and the push is its consequence.

**Detection thesis:** read `requestParameters.policyText`. The discriminator is whether the new
document grants a **push** action to a principal outside the account, and that is in the request —
the event name and its success carry no information at all.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **CloudTrail management events for `ecr.amazonaws.com`.** `SetRepositoryPolicy`,
  `DeleteRepositoryPolicy`, `PutRegistryPolicy` and `PutImageTagMutability` are management events
  and on by default. `requestParameters.policyText` carries the **full document as a JSON string**
  — it is the field the whole detection depends on.
- **ECR image push and pull events**, which are `PutImage` (management) and the layer-upload
  calls. `ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer` are the pull path.
- **A record of each repository's intended policy**, in infrastructure code. `SetRepositoryPolicy`
  replaces the document, so the previous version exists only in the preceding CloudTrail event or
  in IaC — ECR keeps no policy history.
- **Image digests for what is deployed**, per environment. A tag is mutable unless the repository
  sets `IMMUTABLE`; the digest is the only stable identity.

**Alerting (must be pre-configured)**
- **`SetRepositoryPolicy` whose `policyText` grants a push action to a principal outside this account → P0**
- **`SetRepositoryPolicy` whose `policyText` contains `"AWS": "*"` or a wildcard principal → P0**
- **`SetRepositoryPolicy` by a principal outside the provisioning allowlist → P1**
- **`SetRepositoryPolicy` with `force: true`, which bypasses the policy-validation check → P1**

**Response Tooling**
- AWS CLI v2 with **break-glass responder credentials**, held separately from any principal under
  investigation, and `jq`.
- The repository's policy from infrastructure code, to diff live state against.
- A registry-aware client (`docker`, `crane` or `skopeo`) for inspecting image manifests and
  digests, since the image content is not in CloudTrail.

**Known IOC Baselines**
- **Which principals legitimately call `SetRepositoryPolicy`.** In an IaC estate this is one role,
  and it is the tuning surface for the whole detection.
- The account IDs that are legitimately granted cross-account pull, with an owner for each. Push
  across accounts is rarer still and should be an explicitly recorded exception.
- The digest currently deployed for every image tag in production, so a change is a diff.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `SetRepositoryPolicy` whose `policyText` grants `ecr:PutImage` or a layer-upload action to a principal outside this account | CloudTrail (management) | T1098 |
| P0 | `SetRepositoryPolicy` whose `policyText` contains a wildcard principal (`"AWS": "*"`) | CloudTrail (management) | T1098 |
| P1 | `SetRepositoryPolicy` by a principal outside the provisioning allowlist | CloudTrail (management) | T1098 |
| P1 | `SetRepositoryPolicy` with `force: true` — policy validation was deliberately bypassed | CloudTrail (management) | T1098 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `PutImage` on a repository whose policy changed within the preceding 24 hours | CloudTrail (management) | T1525 |
| P2 | `PutImageTagMutability` set to `MUTABLE` on a repository that was immutable | CloudTrail (management) | T1525 |
| P3 | `DeleteRepositoryPolicy` — removes all cross-account access, and is as unexplained as adding it | CloudTrail (management) | T1098 |

### Detection Rule Quality Notes

The source rule is one threshold query and is fully readable, so every row below is auditable
against `_source/original_rules.yml`.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Matches the event name and never the policy | `SetRepositoryPolicy` **replaces** the document, so granting external push and removing a stale grant are the same event with the same success. The rule cannot separate them, and in an IaC estate it fires on every apply | Read `requestParameters.policyText`. The push actions and the principal are in the request; the event name carries nothing |
| Excludes one operator principal by hard-coded ARN | Not an allowlist: it cannot be reviewed, it breaks silently when that identity is rotated or renamed, and it puts an individual's name inside detection logic | A `known_provisioners` block populated before deployment, reviewable and owned |
| No handling of a wildcard principal | `"AWS": "*"` on a repository policy is public push or pull depending on the actions, and it is the highest-severity form of this technique. The rule treats it identically to any other policy write | Its own rule, at the top severity, matched on the principal shape rather than on the account ID |
| Ignores `force` | `force: true` bypasses the check that would otherwise reject a policy which locks the caller out. It has no benign routine use and it is in the same request | Its own rule at high |
| MITRE `T1484` | That technique is identity-provider policy modification. This is a resource policy on a registry — a different object with a different blast radius | `T1098 — Account Manipulation` for the grant, with `T1525 — Implant Internal Image` as the objective it enables |
| Nothing watches the consequence | The grant is the incident; the push is what it was for. A rule that stops at the policy leaves the responder without the work-list | A `PutImage`-after-policy-change trigger at P2, and Query 3 to enumerate what arrived |

**Recommended detection — read the policy document, not the call.**

```yaml
# ECR Repository Policy Applied (T1098)
#
# A REPOSITORY POLICY IS THE REGISTRY'S RESOURCE-BASED POLICY. AWS: "By default, only the AWS
# account that created the repository has access to the repository." `SetRepositoryPolicy`
# replaces that default with a document naming Principals, and the interesting grant is not
# read access - it is `ecr:PutImage` and the three layer-upload actions, because those let a
# principal outside the account WRITE IMAGES into a repository your workloads deploy from.
# Paired with a mutable tag (`../../ecr.stealth.image-tag-overwrite-enabled/`) that is a
# complete container supply-chain compromise established by two API calls.
#
# `Principal: "*"` IS NOT ANONYMOUS, AND THE DISTINCTION MATTERS BOTH WAYS. AWS: "Amazon ECR
# requires that users have permission to make calls to the `ecr:GetAuthorizationToken` API
# through an IAM policy before they can authenticate to a registry and push or pull any images
# from any Amazon ECR repository." A repository policy cannot grant that - it is registry-level
# and IAM-only. So a wildcard principal does not expose the repository to unauthenticated
# internet traffic. It exposes it to EVERY AWS ACCOUNT, because any account holder can grant
# themselves `ecr:GetAuthorizationToken` in their own account. Neither "it is public" nor "it is
# fine" is the right reading; "any AWS customer who knows the URI" is.
#
# ECR KEEPS NO POLICY VERSION HISTORY, and the two ways a policy disappears are NOT
# symmetrical. `DeleteRepositoryPolicy` RETURNS the document it removed - its response elements
# are `policyText`, `registryId`, `repositoryName` - so the delete event preserves what was in
# force. A second `SetRepositoryPolicy`, by contrast, silently REPLACES the previous document
# and carries no trace of it: the only surviving copy is `requestParameters.policyText` in the
# earlier applying event, bounded by your retention. So an overwrite destroys evidence and a
# delete does not, which is why the playbook's first containment step is a capture and why the
# removal rule below exists to point a responder at a record that is still recoverable.
#
# ENCODING AND WHITESPACE - the request side is RAW JSON. `requestParameters.policyText` is the
# document as the client sent it, not percent-encoded, so a `|contains` DOES match it and a
# decode step on the request is wrong. What varies is WHITESPACE: AWS's own API reference shows
# the request compact (`"Principal":"*"`) and the response pretty-printed
# (`"Principal" : "*"`). Every match below is therefore on an ACTION TOKEN - a string that
# carries no interior punctuation and no assumed spacing - and the structural questions (Allow
# vs Deny, which Principal, whether a Condition confines it, `NotAction`) are handed to
# `tools/decode_policy_documents.py`, which parses rather than pattern-matches. A Sigma rule
# that tries to answer them with `|contains` on punctuation is a rule that misses a
# pretty-printed document.
#
# THE SOURCE RULE matches `eventName:"SetRepositoryPolicy"` with a success filter and one
# hard-coded principal exclusion, and never opens the document. Every repository policy applied
# by any IaC run fires it at the same priority as a cross-account push grant, which is how a
# rule gets muted.
title: ECR repository policy grants image push
id: 655b09c0-cefc-4e6e-8927-c28ba5f31195
name: ecr_repo_policy_grants_push
status: experimental
description: >-
  A repository policy was applied whose document names an image-write action. Push rights on a
  registry repository let the grantee replace what your workloads deploy, which is a
  supply-chain grant rather than a sharing grant.
references:
  - https://attack.mitre.org/techniques/T1098/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_SetRepositoryPolicy.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
  - attack.privilege-escalation
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecr.amazonaws.com'
    eventName: 'SetRepositoryPolicy'
  # ACTION TOKENS ONLY. Each of these is a bare string with no interior punctuation, so it
  # matches whether the client sent a compact or a pretty-printed document. `ecr:PutImage` is
  # the write itself; the three layer actions are the upload that precedes it, and a policy
  # granting those without PutImage still hands over half the push path. `ecr:*` covers both.
  write_action:
    requestParameters.policyText|contains:
      - 'ecr:PutImage'
      - 'ecr:InitiateLayerUpload'
      - 'ecr:UploadLayerPart'
      - 'ecr:CompleteLayerUpload'
      - 'ecr:BatchCheckLayerAvailability'
      - 'ecr:*'
  success:
    errorCode: null
  # POPULATE with the pipeline that owns repository policy. Left as-is the rule fires on every
  # push grant, which for a resource policy is the correct default - repository policies are
  # rare, and one that grants writes is rarer still.
  policy_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace, or delete this block entirely
  condition: selection and write_action and success and not policy_pipeline
falsepositives:
  - >-
    A deliberate cross-account publishing arrangement - a shared base-image repository written
    by a platform account. Legitimate and durable; record the grantee account and exclude by
    repository name, not by principal.
  - >-
    An IaC run re-applying an unchanged policy. The document is identical each time, so
    suppress on the policy text rather than on the event.
level: high
---
# FORCED. AWS: "If the policy you are attempting to set on a repository policy would prevent
# you from setting another policy in the future, you must force the SetRepositoryPolicy
# operation. This is intended to prevent accidental repository lock outs." A caller who has to
# pass `force` is applying a document that removes their own ability to change it again. That
# is a lock-out, and outside a deliberate, ticketed change it has no benign reading - it is how
# a resource policy is made durable against the account that owns the resource.
title: ECR repository policy applied with force
id: bc062324-10cb-4f54-84d9-f9b76452c1bf
name: ecr_repo_policy_forced
status: experimental
description: >-
  `SetRepositoryPolicy` was called with `force: true`, which AWS requires only when the policy
  being applied would prevent the caller from setting another policy afterwards.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_SetRepositoryPolicy.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecr.amazonaws.com'
    eventName: 'SetRepositoryPolicy'
  forced:
    requestParameters.force: true
  success:
    errorCode: null
  condition: selection and forced and success
falsepositives:
  - >-
    A deliberate deny-by-default policy applied by a governance pipeline. Rare, and it should
    carry a change record; the alert is that record's counterpart.
level: high
---
# BASE RULE - sequence component only, not for direct alerting. Carries the success filter
# because it feeds a correlation that fires at `high`.
title: ECR repository policy applied
id: e89d6f22-7a6c-48c8-bbff-0288cf51af06
name: ecr_repo_policy_set
status: experimental
description: >-
  Base rule - sequence component only, not for direct alerting. A repository policy was applied
  to a repository.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_SetRepositoryPolicy.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecr.amazonaws.com'
    eventName: 'SetRepositoryPolicy'
  success:
    errorCode: null
  condition: selection and success
level: informational
---
# THRESHOLD BASIS - derived from documented behaviour, not an observed count. There is no
# emulation behind this number. The technique's own baseline is ONE repository: a single push
# grant on the repository production deploys from is the whole attack, and the rule above
# already fires high on it. This correlation is the estate signal - a principal opening several
# repositories in one sitting is enumerating what it can share rather than sharing one thing
# deliberately. Three distinct repositories in thirty minutes sits above any single considered
# grant. `gte`, never `gt`, so a sweep that touches exactly three does not fall through.
title: ECR repository policies applied across multiple repositories by one principal
id: 49936931-0606-4aab-8108-57fabdd690fa
status: experimental
description: >-
  One principal applied repository policies to three or more distinct repositories inside
  thirty minutes. That is an estate being opened, not a repository being shared.
references:
  - https://attack.mitre.org/techniques/T1098/  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
correlation:
  type: value_count
  rules:
    - ecr_repo_policy_set
  group-by:
    - userIdentity.arn
  timespan: 30m
  # `field` belongs INSIDE `condition` for a value_count correlation - it is the field whose
  # DISTINCT values are counted.
  condition:
    gte: 3
    field: requestParameters.repositoryName
level: high
---
# The removal is a permission event AND an evidence event. `DeleteRepositoryPolicy` returns
# the document it removed in `responseElements.policyText`, so this event is the record of what
# was in force at the moment it stopped being in force - frequently the cleanest copy available,
# because an OVERWRITE by a second `SetRepositoryPolicy` retains nothing of the prior document.
# Firing here tells a responder both that access was withdrawn and where the granted text is.
title: ECR repository policy deleted
id: 8196c68e-9b8b-4ed9-9799-7c84256e6937
name: ecr_repo_policy_removed
status: experimental
description: >-
  A repository policy was removed. ECR retains no policy history, but this event's
  `responseElements.policyText` carries the document that was deleted - often the cleanest
  surviving copy of what was granted.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_DeleteRepositoryPolicy.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecr.amazonaws.com'
    eventName: 'DeleteRepositoryPolicy'
  success:
    errorCode: null
  condition: selection and success
falsepositives:
  - >-
    Repository teardown by an IaC pipeline, which deletes the policy before the repository.
    Correlate with a `DeleteRepository` on the same repository within minutes.
level: medium
---
# DENIALS ARE ATTEMPTS AND MUST BE COUNTED SEPARATELY FROM GRANTS. A principal refused on
# fifteen repositories and successful on one opened one repository, not sixteen - and a
# success-only rule, which is what the source ships, cannot tell the two apart because it
# never sees the fifteen. `AccessDeniedException` (HTTP 403) and `NotAuthorized` (HTTP 401)
# are both in ECR's documented common-error set; the bare `AccessDenied` form is what
# IAM-evaluated denials produce across AWS and is widely observed but is NOT in ECR's
# documented list. Matched prefix-tolerantly so all three land here.
title: ECR repository policy write denied
id: 4f10f9bb-24e8-4a07-bd31-edb5867dd584
name: ecr_repo_policy_denied
status: experimental
description: >-
  A `SetRepositoryPolicy` or `DeleteRepositoryPolicy` call was refused. Repeated refusals
  across repositories are a principal mapping its boundary, not an operator making a mistake.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/CommonErrors.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1098
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecr.amazonaws.com'
    eventName:
      - 'SetRepositoryPolicy'
      - 'DeleteRepositoryPolicy'
  denied:
    errorCode|contains:
      - 'AccessDenied'
      - 'NotAuthorized'
  condition: selection and denied
falsepositives:
  - >-
    A developer discovering they lack repository-policy rights. One or two events; a pattern
    across many repositories in one window is not that.
level: medium
```

What this set structurally cannot do: it cannot tell you what is *inside* an image. CloudTrail
records that a layer was uploaded and its digest, never its content — Query 3 pulls the manifest,
and inspecting the filesystem is a registry-client job outside AWS. It also cannot recover the
**previous** policy: `SetRepositoryPolicy` replaces the document and ECR keeps no history, so the
prior state exists only in the preceding CloudTrail event or in infrastructure code.

---

### Key Investigation Queries

> ECR is regional and these are **management** events, on by default. Extraction uses
> `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50
> events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: what the policy now says, and who wrote it

```bash
REGION="us-east-1"
SINCE=$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SetRepositoryPolicy \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, caller: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     repo: .requestParameters.repositoryName,
     force: (.requestParameters.force // false),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress,
     policy: (.requestParameters.policyText // "null" | fromjson? // .)}' | \
  jq -s 'sort_by(.time)'
```

`policyText` is a JSON **string** inside the event, so it is parsed with `fromjson?` — the `?`
matters, because a malformed document still produces an event and an unguarded parse aborts the
whole pipeline on it. Read each statement's `Principal` and `Action`: a `Principal.AWS` that is
not this account, paired with `ecr:PutImage` or any `ecr:*LayerUpload*` action, is the finding.
`force: true` means policy validation was bypassed deliberately.

#### Query 2 — Sweep: every repository policy in the account, right now

```bash
REGION="us-east-1"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)

for R in $(aws ecr describe-repositories --region "$REGION" --output json | \
           jq -r '.repositories[].repositoryName'); do
  POL=$(aws ecr get-repository-policy --repository-name "$R" --region "$REGION" \
        --output json 2>/dev/null | jq -r '.policyText // empty')
  [ -z "$POL" ] && continue
  echo "$POL" | jq -r --arg r "$R" --arg acct "$ACCOUNT" '
    (.Statement // [] | if type == "object" then [.] else . end)[]
    | select(.Effect == "Allow")
    | ((.Principal.AWS // .Principal // "-") | if type == "string" then [.] else . end) as $p
    | ((.Action // []) | if type == "string" then [.] else . end) as $a
    | select($p | any(. == "*" or (tostring | contains($acct) | not)))
    | "[!] \($r)  principal=\($p | join(","))  actions=\($a | join(","))"'
done
```

`Statement`, `Principal` and `Action` are each shape-guarded, because IAM allows every one of
them as either a scalar or an array and an unguarded `any()` over a single object iterates its
values and fails silently. A `[!]` line naming `*` or an account that is not this one is a
cross-account grant; check it against the recorded exceptions from §1 before treating it as the
finding.

#### Query 3 — Inspect: what was pushed while the grant stood

```bash
REGION="us-east-1"
REPO="<repositoryName-from-Query-1>"

echo "== images in the repository, newest first =="
aws ecr describe-images --repository-name "$REPO" --region "$REGION" --output json | \
  jq -r '.imageDetails | sort_by(.imagePushedAt) | reverse | .[:20][] |
    "\(.imagePushedAt)  \(.imageDigest[0:23])  tags=\((.imageTags // ["<untagged>"]) | join(","))  \(.imageSizeInBytes) bytes"'

echo
echo "== push events, with the pushing principal =="
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutImage \
  --start-time "$(date -u -v-30d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg r "$REPO" '.Events[].CloudTrailEvent | fromjson |
    select(.requestParameters.repositoryName == $r) |
    {time: .eventTime, caller: .userIdentity.arn,
     account: .userIdentity.accountId, recipient: .recipientAccountId,
     tag: .requestParameters.imageTag,
     digest: .responseElements.image.imageId.imageDigest}'
```

`userIdentity.accountId` differing from `recipientAccountId` is the cross-account push, recorded
in the repository owner's trail — that inequality is the proof the grant was used. A tag reused
against a new digest is the dangerous shape: the tag looks unchanged to anything that references
it by name.

#### Query 4 — Full session reconstruction of the principal

```bash
REGION="us-east-1"
ACCESS_KEY_ID="<access-key-from-Query-1>"
SINCE=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$SINCE" --region "$REGION" --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, src: .eventSource, event: .eventName,
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s 'group_by(.src) | map({service: .[0].src, calls: length,
                               events: (map(.event) | unique)})'
```

Keyed on the access key rather than the ARN, since one credential spans many sessions. A
principal that rewrote a registry policy has usually touched IAM as well — look for
`PutImageTagMutability` weakening immutability, and for anything in `ecs` or `eks` that would
force a redeploy and pull the new image sooner.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Revert the policy first, then find out whether anything was pushed under it. The revert is one
call and does not depend on the investigation.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being investigated.

#### Step 1 — Capture the current policy before replacing it

```bash
REGION="us-east-1"
REPO="<repositoryName>"
CASE_DIR="./ir-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$CASE_DIR"

aws ecr get-repository-policy --repository-name "$REPO" --region "$REGION" \
  --output json > "$CASE_DIR/policy-before.json" 2>/dev/null \
  && echo "[OK] saved to $CASE_DIR/policy-before.json" \
  || echo "[i] no policy currently attached"
```

`SetRepositoryPolicy` replaces the document and ECR keeps no history, so this capture is the only
copy of the malicious policy once the revert lands.

#### Step 2 — Restore the intended policy from infrastructure code

```bash
REGION="us-east-1"
REPO="<repositoryName>"
GOOD="<path-to-intended-policy.json>"

if [ ! -f "$GOOD" ]; then
  echo "[FAIL] no known-good policy file. If the repository should have NO cross-account access,"
  echo "       delete the policy outright rather than guessing at one:"
  echo "       aws ecr delete-repository-policy --repository-name $REPO --region $REGION"
else
  aws ecr set-repository-policy --repository-name "$REPO" --region "$REGION" \
    --policy-text "file://$GOOD" --output json | \
    jq -r '"[OK] policy replaced on \(.repositoryName)"'
fi
```

Note the asymmetry: **no `force`**. If the intended policy would lock the caller out, ECR refuses
it, and that refusal is information worth having rather than overriding.

#### Step 3 — Restore tag immutability, if it was weakened

```bash
REGION="us-east-1"
REPO="<repositoryName>"

MUT=$(aws ecr describe-repositories --repository-names "$REPO" --region "$REGION" \
      --output text --query 'repositories[0].imageTagMutability')
if [ "$MUT" = "MUTABLE" ]; then
  echo "[!] tags are MUTABLE — a pushed image can replace one already deployed under the same tag."
  echo "    Setting IMMUTABLE prevents further overwrites but does NOT undo one already made:"
  echo "    aws ecr put-image-tag-mutability --repository-name $REPO --image-tag-mutability IMMUTABLE --region $REGION"
else
  echo "[OK] tags are $MUT"
fi
```

#### Step 4 — Contain the principal

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')      # user ARN: name = last segment
  aws iam put-user-policy --user-name "$U" --policy-name IR-Deny-All \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')       # role ARN: name = 2nd segment
  cat > /tmp/revoke.json <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["*"],"Resource":["*"],
 "Condition":{"DateLessThan":{"aws:TokenIssueTime":"REVOKE_BEFORE"}}}]}
JSON
  sed -i.bak "s/REVOKE_BEFORE/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" /tmp/revoke.json
  aws iam put-role-policy --role-name "$R" --policy-name AWSRevokeOlderSessions \
    --policy-document file:///tmp/revoke.json
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

---

## 4. Eradication

### Remove Attacker Access

#### Treat every image pushed during the window as untrusted

Query 3's list bounded by the policy change and the revert is the work-list. An image is not made
safe by the policy being fixed — if it is running, it is running. Redeploy each affected service
from a digest you can trace to a build you control, not from a tag.

#### Check every other repository

Re-run Query 2 across every Region in use. A principal that rewrote one repository policy usually
tried others, and the ones that succeeded may not have alerted if their policies were already
permissive.

#### Right-size who can write repository policies

`ecr:SetRepositoryPolicy` and `ecr:PutImageTagMutability` belong to the platform role that owns
the registry, not to application deploy credentials. Query 4's principal is the starting point.

#### Remove emergency policies once clean

Delete `IR-Deny-All` and `AWSRevokeOlderSessions` once the principal is rebuilt or retired.

---

## 5. Recovery

### Restore Clean State

#### Verify the live policy matches the intended one

```bash
REGION="us-east-1"
REPO="<repositoryName>"
GOOD="<path-to-intended-policy.json>"

LIVE=$(aws ecr get-repository-policy --repository-name "$REPO" --region "$REGION" \
       --output json 2>/dev/null | jq -r '.policyText' | jq -S -c . 2>/dev/null)
WANT=$(jq -S -c . "$GOOD" 2>/dev/null)
[ -n "$LIVE" ] && [ "$LIVE" = "$WANT" ] && echo "[OK] repository policy matches the intended document" \
                                        || echo "[FAIL] live policy differs from $GOOD"
```

Both sides are sort-keyed and compacted before comparison, so key ordering and whitespace do not
produce a false `[FAIL]`.

#### Verify no repository grants push outside the account

```bash
REGION="us-east-1"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
BAD=0
for R in $(aws ecr describe-repositories --region "$REGION" --output json | \
           jq -r '.repositories[].repositoryName'); do
  POL=$(aws ecr get-repository-policy --repository-name "$R" --region "$REGION" \
        --output json 2>/dev/null | jq -r '.policyText // empty')
  [ -z "$POL" ] && continue
  HIT=$(echo "$POL" | jq -r --arg acct "$ACCOUNT" '
    [(.Statement // [] | if type == "object" then [.] else . end)[]
     | select(.Effect == "Allow")
     | select(((.Action // []) | if type == "string" then [.] else . end)
              | any(test("PutImage|LayerUpload|ecr:\\*|^\\*$")))
     | select((((.Principal.AWS // .Principal // "-") | if type == "string" then [.] else . end))
              | any(. == "*" or (tostring | contains($acct) | not)))] | length')
  [ "${HIT:-0}" -gt 0 ] && { echo "[FAIL] $R grants push outside this account"; BAD=$((BAD+1)); }
done
[ "$BAD" -eq 0 ] && echo "[OK] no repository grants push outside this account"
```

#### Confirm the corrected detection fires

```bash
echo "Synthetic test — the rule MUST fire on:"
echo "  eventSource=ecr.amazonaws.com  eventName=SetRepositoryPolicy  no errorCode"
echo "  requestParameters.policyText granting ecr:PutImage to \"AWS\": \"arn:aws:iam::999988887777:root\""
echo "and MUST fire at the top severity on:"
echo "  the same call with \"AWS\": \"*\""
echo "The rule MUST NOT fire on:"
echo "  SetRepositoryPolicy by an ARN in known_provisioners whose policyText grants"
echo "  only ecr:BatchGetImage to an account on the recorded pull-exception list"
echo "  (a read grant by the provisioning role — the case the source rule cannot distinguish)"
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A repository policy granted push to an outside principal | `ecr:SetRepositoryPolicy` was available to a principal that does not own the registry |
| The change was not distinguishable from routine maintenance | The detection matched the event name and never read `policyText`, and the call replaces rather than merges |
| The exclusion list broke silently | A single operator principal was hard-coded by ARN rather than kept as a reviewable allowlist |
| A pushed image could replace a deployed one | Tag mutability was `MUTABLE`, so the tag referenced by the deployment resolved to new content |
| The previous policy could not be recovered | ECR keeps no policy history and the document is replaced, so the prior state existed only in CloudTrail |

### Recommended Guardrails

**Fence registry policy writes**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["ecr:SetRepositoryPolicy", "ecr:DeleteRepositoryPolicy",
             "ecr:PutRegistryPolicy", "ecr:PutImageTagMutability"],
  "Resource": "*",
  "Condition": { "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/PlatformAutomation"] } }
}
```

**Structural controls**
- Set `imageTagMutability` to `IMMUTABLE` on every repository whose images run in production. It
  turns a tag into a stable reference and removes the overwrite path entirely.
- Keep repository policies in infrastructure code and reconcile on a schedule. The API replaces
  the document and keeps no history, so IaC is the only durable record of what it should say.
- Require signed images and verify at deploy time. A push grant then yields an image that will not
  run, which is a materially smaller problem.

**Detection improvements**
- Read the policy document, not the call. For any API that **replaces** a document, the event name
  cannot distinguish a grant from a revocation and the request body always can.
- Never hard-code a single principal as an exclusion. It is unreviewable, it breaks on rotation,
  and it names an individual inside detection logic.
- Pair the grant rule with a `PutImage` rule scoped to repositories whose policy recently changed.
  The grant is the alert; the push is the work-list.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1098 — Account Manipulation |
| MITRE tactic | Persistence (TA0003), Privilege Escalation (TA0004) |
| Primary API | `ecr:SetRepositoryPolicy`; `ecr:PutImage` and the layer-upload calls as the consequence |
| Event source | ecr.amazonaws.com, management plane, on by default |
| Key discriminator | `requestParameters.policyText` granting a push action to a principal outside the account. The event name and its success carry nothing |
| Ground-truth signal | `get-repository-policy` — live state, since the API replaces the document and ECR keeps no history |
| "Was it used" pivot | `PutImage` on the repository with `userIdentity.accountId` differing from `recipientAccountId` — a cross-account push recorded in the owner's trail |
| Blast radius | Every workload that pulls from the repository, at its next deployment. With mutable tags, that includes workloads already running when they next restart |
| Error strings | `RepositoryPolicyNotFoundException` on a repository with no policy; `InvalidParameterException` on a malformed document; `RepositoryNotFoundException`. Denials are `AccessDenied` / `AccessDeniedException` — match both |

**MITRE mapping note:** the source carries `T1484 — Domain or Tenant Policy Modification`, which
describes identity-provider policy. This is a resource policy on a container registry — a
different object, a different blast radius, and reached through a different API surface.
`T1098 — Account Manipulation` covers granting a principal access it did not have, and
`T1525 — Implant Internal Image` names the objective a push grant exists to enable. Both verified
live 2026-08-30.

### Residual Risk

Any image pushed while the grant stood is untrusted, and a policy revert does not stop one that is
already running — only a redeploy from a verified digest does. If tags were mutable, an image
already deployed may have been replaced under the same tag, so the tag a manifest references is not
evidence of its content. The previous policy is unrecoverable unless the preceding CloudTrail event
is still in retention or infrastructure code holds it. And a pull grant left in place after the push
grant is removed still lets the actor read every image in the repository, which for a private
registry is source-adjacent material.
