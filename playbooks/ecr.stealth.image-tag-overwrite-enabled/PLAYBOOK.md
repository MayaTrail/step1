# IR Playbook: ECR Image Tag Overwrite Enabled — Container Supply-Chain Substitution via `ecr:PutImageTagMutability`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Software supply-chain tampering (a repository's tag-integrity setting is relaxed so an existing image tag can be repointed at attacker-supplied content) |
| Threat Actor | N/A — single use case, not actor-attributed |
| Platform | aws |
| Severity | **High**, against the source rule's **P4** — the largest priority disagreement in this set. The setting change is silent and looks reversible; it is the enabling half of a compromise whose other half leaves no attributable trace on the consumer side, because every workload that pulls `:latest` or `:prod` afterwards runs the substituted image and the pull record names the tag requested rather than the digest served. A P4 on the only control standing between a registry and an undetectable image substitution is a miscalibration, not a judgement call |
| MITRE Tactics | Persistence (TA0003), Defense Impairment (TA0112) |
| MITRE Techniques | T1525 (primary), T1685 (secondary) — both verified live 2026-08-29 |
| Services in Scope | ECR, CloudTrail (management — ECR has no data-event category), ECS, EKS, Lambda (container image functions), App Runner, IAM, Organizations (SCP), and every build pipeline that publishes to the affected repository |
| Tier | **Tier 1 (full)** — promoted on tests 3 and 5 of `07-TIERS.md`, plus test 2. See the promotion note below |

**What the technique does:** the actor calls `ecr:PutImageTagMutability` with `imageTagMutability` set to
`MUTABLE`, `MUTABLE_WITH_EXCLUSION`, or — the targeted form — `IMMUTABLE_WITH_EXCLUSION` with
`imageTagMutabilityExclusionFilters` naming a floating tag such as `latest`. That one call
re-opens the tag namespace. The actor then pushes an image carrying the existing tag: the layer
uploads run, `PutImage` completes, and ECR repoints the tag from the digest the pipeline
published to the digest the actor supplied. Nothing else about the repository changes — same
name, ARN, `<acct>.dkr.ecr.<region>.amazonaws.com/<repo>` URI, repository policy, encryption,
scanning configuration and lifecycle policy. Every consumer's reference still resolves, and
from that moment each ECS task placement, EKS pod restart and Lambda cold start that pulls by
that tag runs the actor's code under that workload's own execution role.

**Why this is potent, and why the usual reflexes miss it.** The first reflex is to check the
image is still there, and it is: `describe-images` lists the tag, `list-images` lists the tag,
the console shows it, every deployment reference resolves. A tag is a *pointer* and the attack
repoints it, so every check that asks "does the tag exist" returns a clean answer over a live
compromise; the only field that moved is `imageDigest`, exactly as `CodeSha256` is the only
field that moves in the Lambda code-overwrite technique. The
second reflex — "which workloads pulled it?" — meets the fact that the pull *is* logged (ECR
has no CloudTrail data-event category, so `BatchGetImage` and `GetDownloadUrlForLayer` are
management events present by default) but the event carries
`requestParameters.imageIds[].imageTag` and `"responseElements": null`: the tag the client
asked for, never the digest the registry served. The third reflex — "the repository is
immutable, we're fine" — is what `IMMUTABLE_WITH_EXCLUSION` defeats, because the setting still
reads as an immutable variant while the named tags stay writable.

**Detection is the mutability value and the digest, not the event name.**
`PutImageTagMutability` is a legitimate call; what separates a migration from an attack is
**which of the four documented values it lands on** — `MUTABLE`, `MUTABLE_WITH_EXCLUSION` and
`IMMUTABLE_WITH_EXCLUSION` all permit overwrite, `IMMUTABLE` alone does not — and, as ground
truth, **a live tag resolving to a digest the build system never produced**. The source rule
matches only the literal value `mutable` on only the `PutImageTagMutability` path, so it
misses both exclusion-filter forms, misses `CreateRepository` (where `MUTABLE` is the
documented default reached by omitting the parameter), and discards
`ImageTagAlreadyExistsException` — the refusal an immutable repository returns when somebody
attempts precisely this.

> **Tier-1 promotion, and which tests.** **Test 3 — the blast radius is not in the event:**
> which workloads consume which tag lives in ECS task definitions, EKS pod specs, Lambda
> `ImageUri` values and App Runner services, and after containment repoints or deletes the tag
> the mapping that would have told you what was exposed is gone with it. **Test 5 — a
> structural blind spot worth a page of honesty:** the consumer side records the tag, not the
> digest, so "did anything run the substituted image" is answerable only as a time window.
> **Test 2 also applies** — re-imposing `IMMUTABLE` before repointing the tag makes the tag
> unwritable and blocks the repair, so containment ordering is load-bearing (§3).

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail capturing ECR **management** events. **ECR has no CloudTrail
  data-event category at all** — `AWS::ECR::Repository` is absent from CloudTrail's supported
  data-event resource types — so pulls, pushes and configuration changes are all management
  events, on by default, with nothing to enable and nothing to pay for. The trail must be
  **`ReadWriteType = All`**: `BatchGetImage` and `GetDownloadUrlForLayer` are read events, and a
  write-only trail drops them, leaving a zero indistinguishable from "nothing pulled it"
- `PutImageTagMutability` carries `requestParameters.imageTagMutability` (required; one of
  `MUTABLE | IMMUTABLE | IMMUTABLE_WITH_EXCLUSION | MUTABLE_WITH_EXCLUSION`) and
  `requestParameters.imageTagMutabilityExclusionFilters[]` (`{filter, filterType}`, one to five
  members, `filterType` = `WILDCARD`), plus `repositoryName` and `registryId`; the response
  repeats them flat. `CreateRepository` carries `requestParameters.imageTagMutability` **only
  when the caller set it** — AWS: *"If this parameter is omitted, the default setting of
  `MUTABLE` will be used"* — so the authoritative field there is the **nested**
  `responseElements.repository.imageTagMutability`
- `PutImage` carries `requestParameters.{repositoryName, imageTag, imageManifest}` and, as
  ground truth, the **doubly nested** `responseElements.image.imageId.imageDigest` — there is
  no flat `responseElements.imageDigest`, and a flat path yields `null` silently. `BatchGetImage`
  carries `requestParameters.imageIds[].imageTag` (or `.imageDigest` if the client pinned) and,
  per AWS's published example, `"responseElements": null`: **the digest served is not logged**
- A **known-good digest baseline per tag**, published by the build system into a CMDB or
  artifact registry — the `CodeSha256` of this technique; without it none of §5's assertions
  can be made — plus an inventory of which ECS task definitions, EKS workloads, Lambda
  functions and App Runner services reference each repository, and by tag or by digest

**Alerting (must be pre-configured)**
- **`PutImageTagMutability` landing on `MUTABLE`, `MUTABLE_WITH_EXCLUSION` or `IMMUTABLE_WITH_EXCLUSION` → P0**
- **An `imageTagMutabilityExclusionFilters` entry naming a floating production tag (`latest`, `prod`, `stable`, `release`, `main`) → P0**
- **A production tag resolving to a digest the build system never published → P0**
- **Ordered sequence `PutImageTagMutability` → `PutImage` on the same repository within thirty minutes → P1**
- **`PutImage` refused with `ImageTagAlreadyExistsException` → P1**

**Response Tooling**
- AWS CLI v2 and `jq`, with break-glass responder credentials separate from every principal
  under investigation and from the CI/CD roles; `crane`, `skopeo` or `docker` on a sandboxed
  host that can pull **by digest**, the only way to fetch a specific image once a tag moved
- The known-good digest baseline, the trusted source to rebuild from, and read access to ECS,
  EKS, Lambda and App Runner in every account and region that consumes the registry

**Known IOC Baselines**
- Which principals may change repository configuration — normally the IaC pipeline and nothing
  else — and the digest each floating tag pointed at before the incident window opened
- Which repositories front **pull-through cache rules**: AWS recommends `MUTABLE` for those so
  ECR can refresh the cached upstream tag, and they are the one legitimate standing exception.
  Enumerate with `aws ecr describe-pull-through-cache-rules`

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `PutImageTagMutability` landing on `MUTABLE`, `MUTABLE_WITH_EXCLUSION` or `IMMUTABLE_WITH_EXCLUSION` | CloudTrail (management) | T1525 |
| P0 | An `imageTagMutabilityExclusionFilters` entry naming a floating production tag (`latest`, `prod`, `stable`, `release`, `main`) | CloudTrail (management) | T1685 |
| P0 | A production tag resolving to a digest the build system never published | Registry drift check | T1525 |
| P1 | Ordered sequence `PutImageTagMutability` → `PutImage` on the same repository within thirty minutes | CloudTrail (management) | T1525 |
| P1 | `PutImage` refused with `ImageTagAlreadyExistsException` | CloudTrail (management) | T1525 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `CreateRepository` whose `responseElements.repository.imageTagMutability` permits overwrite | CloudTrail (management) | T1525 |
| P2 | `BatchGetImage` / `GetDownloadUrlForLayer` on the affected repository inside the exposure window | CloudTrail (management) | T1525 |
| P2 | `PutImageTagMutability` denied (`AccessDeniedException` / `NotAuthorized`) across several repositories — boundary mapping | CloudTrail (management) | T1685 |
| P3 | `DescribeRepositories` enumeration by a principal that has never pushed | CloudTrail (management) | T1525 |

### Detection Rule Quality Notes

The source rule watches one API, one of four values, and throws away the error that proves the
attack was attempted.

| Issue | Impact | Correction |
|-------|--------|-----------|
| Matches `requestParameters.imageTagMutability:"mutable"` only | Misses `MUTABLE_WITH_EXCLUSION` and `IMMUTABLE_WITH_EXCLUSION`, both of which permit overwrite. `IMMUTABLE_WITH_EXCLUSION` with `filter=latest` is the *targeted* attack and it leaves the repository reporting itself immutable, so the rule is silent on the sharpest form | Match all three overwrite-permitting values; ship a second rule on an exclusion filter naming a floating tag |
| Matches `PutImageTagMutability` only | Mutability is equally a `CreateRepository` parameter. A repository created `MUTABLE` never emits `PutImageTagMutability` at all, so the rule never fires for it | Add the `CreateRepository` path as a sibling rule keyed on the response |
| Reads the request parameter | `MUTABLE` is the documented default *when the parameter is omitted*, so on the ordinary creation path the field is **absent** and the rule reads `null` over an overwritable repository | Key the creation path on the nested `responseElements.repository.imageTagMutability` |
| `NOT _exists_:errorCode` | Discards `ImageTagAlreadyExistsException`, which ECR returns only when a tag-immutable repository refuses an overwrite — the single event in this set that proves an attempt rather than a preparation. Also discards denials, which show a principal mapping its boundary across repositories | Ship the error as its own rule; count denials separately from successes |
| Excludes one hard-coded principal ARN | An allowlist of exactly one, unmaintainable, and it exempts that principal from the alert completely — if it is ever compromised the rule is blind to it | Replace with a named configuration-owner allowlist, reviewed like any other allowlist |
| No sequence, no content ground truth | A setting change and a supply-chain compromise are the same alert; the digest is never inspected | Add the `PutImageTagMutability` → `PutImage` correlation and the digest drift check |
| P4 priority | Triaged below routine noise despite being the enabling step of an undetectable substitution | P0 for the weakening, P0 for the carve-out |

**Recommended detection — a repository's tag mutability weakened to permit overwrite.**

```yaml
# ECR Image Tag Overwrite Enabled (T1525 / T1685)
#
# THE TAG IS A POINTER; THE DIGEST IS THE CONTENT. An ECR image is identified by its
# `imageDigest` — the sha256 of its manifest. An image *tag* is a mutable label pointing at
# a digest, and when a repository permits overwriting, a `PutImage` carrying an existing tag
# repoints that label at a new digest. Nothing else changes: the repository name, its ARN,
# its URI, its policy, its encryption and its scan configuration are all untouched, and the
# reference every consumer holds - `<acct>.dkr.ecr.<region>.amazonaws.com/app:latest` -
# still resolves. This is the registry equivalent of the Lambda code-overwrite technique,
# and the digest plays the part `CodeSha256` plays there: it is the only field that moves.
#
# THE CONSUMER SIDE EMITS NOTHING ATTRIBUTABLE. Every task, pod or function that pulls
# `:latest` after the overwrite runs the attacker's image. That pull IS logged - ECR has no
# CloudTrail data-event category at all, so `BatchGetImage` and `GetDownloadUrlForLayer` are
# management events, present by default (see the note file, and the `A1/A2` rule this
# corrects). But AWS's own published pull event carries `"responseElements": null` and
# `requestParameters.imageIds[].imageTag` - the TAG the client asked for, never the DIGEST
# the registry served. So the log answers "something pulled :latest at 14:02"; it does not
# answer "it received the malicious digest". The link is the overwrite timestamp and nothing
# else. That is the blind spot this rule set is honest about rather than papering over.
#
# FOUR SETTINGS, NOT TWO. `imageTagMutability` is documented with the valid values
# `MUTABLE | IMMUTABLE | IMMUTABLE_WITH_EXCLUSION | MUTABLE_WITH_EXCLUSION`. Overwriting is
# possible under three of them: MUTABLE (every tag), MUTABLE_WITH_EXCLUSION (every tag but
# the filtered ones) and IMMUTABLE_WITH_EXCLUSION (ONLY the filtered ones). The last is the
# targeted form and the quietest: the repository still reports itself immutable, and AWS's
# own CLI example for it is `--image-tag-mutability IMMUTABLE_WITH_EXCLUSION
# --image-tag-mutability-exclusion-filters filterType=WILDCARD,filter=latest` - which is
# precisely "make everything immutable except the one tag production follows".
#
# TWO PATHS SET IT. `PutImageTagMutability` changes it on an existing repository;
# `CreateRepository` sets it at birth, and AWS documents that "If this parameter is omitted,
# the default setting of MUTABLE will be used". So on the ordinary creation path
# `requestParameters.imageTagMutability` is ABSENT and the repository is still overwritable -
# a rule keyed on the request parameter reads `null` and stays silent. The authoritative
# field for the creation path is the RESPONSE, nested:
# `responseElements.repository.imageTagMutability`.
#
# THE SOURCE RULE matches `eventName:"PutImageTagMutability" AND
# requestParameters.imageTagMutability:"mutable"` with a success filter. It therefore misses
# both exclusion-filter values, misses the CreateRepository path entirely, misses the default,
# and discards `ImageTagAlreadyExistsException` - the error an immutable repository returns
# when somebody tries exactly this attack and is refused, which is the single highest-value
# event in the whole set.
title: ECR repository tag mutability weakened to permit overwrite
id: 8c51cb49-4489-402c-956a-8e483ff9a710
name: ecr_tag_mutability_weakened
status: experimental
description: >-
  A repository's `imageTagMutability` was set to a value that permits an existing image tag
  to be repointed at a new digest. Every consumer that pulls by that tag afterwards runs
  whatever was pushed last, and the consumer side records the tag it asked for, not the
  digest it received.
references:
  - https://attack.mitre.org/techniques/T1525/  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutImageTagMutability.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1525
  - attack.defense-impairment
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecr.amazonaws.com'
    eventName: 'PutImageTagMutability'
  # All three overwrite-permitting values. The two _WITH_EXCLUSION forms are what the source
  # rule's single `mutable` match misses, and IMMUTABLE_WITH_EXCLUSION is the dangerous one:
  # the repository continues to report itself immutable while the named tags stay writable.
  overwritable:
    requestParameters.imageTagMutability:
      - 'MUTABLE'
      - 'MUTABLE_WITH_EXCLUSION'
      - 'IMMUTABLE_WITH_EXCLUSION'
  success:
    errorCode: null
  # POPULATE with the roles that own repository configuration - normally the IaC pipeline and
  # nothing else. Left as-is the rule fires on every weakening, which is the correct default:
  # moving a repository from IMMUTABLE toward MUTABLE is not a routine deployment step.
  config_pipeline:
    userIdentity.arn|contains:
      - ':role/iac-deploy'          # replace, or delete this block entirely
  condition: selection and overwritable and success and not config_pipeline
falsepositives:
  - >-
    A repository fronting a pull-through cache rule. AWS recommends MUTABLE for those,
    because ECR must be able to update the cached copy of an upstream tag. Enumerate them
    with `aws ecr describe-pull-through-cache-rules` and exclude by repository name, not by
    principal.
  - >-
    A deliberate, ticketed relaxation during a migration. Traceable and rare; the alert is
    the record that it happened.
level: high
---
# The targeted carve-out. This fires when an exclusion filter names a FLOATING PRODUCTION
# TAG - the class of tag whose whole purpose is that consumers follow it without pinning.
# Carving `latest` out of immutability is not a weaker version of setting MUTABLE; it is a
# stronger, narrower attack, because the repository's headline setting still reads IMMUTABLE
# and any control or dashboard that checks only that field reports the repository as
# protected. Covers both paths - the setting can be established at CreateRepository as well
# as changed later.
#
# FIELD-SHAPE WARNING. `imageTagMutabilityExclusionFilters` is an ARRAY OF OBJECTS
# (`{filter, filterType}`, 1-5 members, filterType `WILDCARD`). How your pipeline flattens
# that array decides whether `|contains` reaches the `filter` values; on a backend that
# serialises the array to a string it matches, on one that explodes it into
# `...ExclusionFilters.0.filter` it does not. Confirm against a real event before relying on
# this rule alone, and treat the rule above as the load-bearing one.
title: ECR tag immutability carved out for a floating production tag
id: 3e039b42-5bfe-4a77-9557-f526fce68b03
name: ecr_tag_mutability_carveout
status: experimental
description: >-
  An image-tag mutability exclusion filter names a floating tag such as `latest` or `prod`.
  Under IMMUTABLE_WITH_EXCLUSION this makes exactly those tags overwritable while the
  repository still reports itself immutable.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutImageTagMutability.html  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1525
  - attack.defense-impairment
  - attack.t1685
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ecr.amazonaws.com'
    eventName:
      - 'PutImageTagMutability'
      - 'CreateRepository'
  carveout:
    requestParameters.imageTagMutability:
      - 'IMMUTABLE_WITH_EXCLUSION'
      - 'MUTABLE_WITH_EXCLUSION'
  # Substring match, so `prod` also catches `production` and `*prod*`. Extend with your own
  # release-channel tag names.
  floating_tag:
    requestParameters.imageTagMutabilityExclusionFilters|contains:
      - 'latest'
      - 'prod'
      - 'stable'
      - 'release'
      - 'main'
  success:
    errorCode: null
  condition: selection and carveout and floating_tag and success
falsepositives:
  - >-
    A team deliberately keeping `latest` writable in a development registry while pinning
    release tags. Legitimate, and worth knowing about; scope the rule to production accounts.
level: high
---
# BASE RULE - sequence component only, not for direct alerting. It fires on every repository
# created with default settings, because MUTABLE is the documented default when the parameter
# is omitted. It is here for two reasons: it feeds the inventory sweep in ../PLAYBOOK.md
# Query 2, and it keys on `responseElements.repository.imageTagMutability` - the NESTED
# response field - rather than the request parameter, which is absent on exactly that
# default path. Keying the check on the request parameter is the defect this rule exists to
# not repeat.
title: ECR repository created in an overwrite-permitting state
id: f0d5cc45-be1c-44f8-9507-70089773bc6b
name: ecr_repo_created_overwritable
status: experimental
description: >-
  Base rule - sequence component only, not for direct alerting. A repository was created in
  a state that permits tag overwrite, including the default state reached by omitting the
  parameter entirely.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_CreateRepository.html  # retrieved 2026-08-29
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
  overwritable:
    responseElements.repository.imageTagMutability:
      - 'MUTABLE'
      - 'MUTABLE_WITH_EXCLUSION'
      - 'IMMUTABLE_WITH_EXCLUSION'
  success:
    errorCode: null
  condition: selection and overwritable and success
falsepositives:
  - >-
    Every repository created without an explicit `--image-tag-mutability IMMUTABLE`. That is
    the majority of them, which is why this is informational and why the account-wide sweep,
    not this rule, is the operational control.
level: informational
---
# BASE RULE - sequence component only, not for direct alerting. Carries the success filter
# because it feeds a `high` correlation: without it a denied push followed by a legitimate
# one would fire high.
title: ECR image pushed
id: 76d9ccbf-c958-42fe-ab08-968085f27d15
name: ecr_put_image
status: experimental
description: >-
  Base rule - sequence component only, not for direct alerting. A `PutImage` completed,
  which is the final call of every image push.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutImage.html  # retrieved 2026-08-29
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
  condition: selection and success
level: informational
---
# THE ATTACK FINGERPRINT. Mutability weakened, then an image pushed to the same repository.
# This is the registry analogue of the reference corpus's `GetFunction -> UpdateFunctionCode`
# sequence, and it is the sequence that turns a configuration change into a supply-chain
# compromise. Grouped by `requestParameters.repositoryName`, which both events carry under
# the identical path - the two do NOT share a principal in the interesting case, because the
# actor may weaken the setting under one identity and push under the CI role's credentials.
#
# TIMESPAN BASIS - derived from documented behaviour, not an observed count. There is no
# emulation behind this number. Thirty minutes is chosen because the weakening has no purpose
# other than the push that follows it, and an operator relaxing mutability for a legitimate
# migration does not then push within the half hour without a change record. Widen it if your
# deploy pipelines are slow; narrowing it below the p99 push duration for a large image will
# drop real sequences, since `PutImage` is the LAST call of a push that began with the layer
# uploads.
title: ECR tag mutability weakened and immediately used to push
id: 220643a3-23b1-452b-84d0-4180d75a0855
status: experimental
description: >-
  A repository's tag mutability was relaxed and an image was pushed to that same repository
  within thirty minutes. The configuration change and the push together are the overwrite.
references:
  - https://attack.mitre.org/techniques/T1525/  # retrieved 2026-08-29
tags:
  - attack.persistence
  - attack.t1525
correlation:
  type: temporal_ordered
  rules:
    - ecr_tag_mutability_weakened
    - ecr_put_image
  group-by:
    - requestParameters.repositoryName
  timespan: 30m
level: high
---
# THE ERROR IS THE EVIDENCE. AWS: "After tag immutability is turned on, the
# `ImageTagAlreadyExistsException` error is returned if you push an image with a tag that is
# already in the repository." That error has exactly one cause - somebody tried to repoint an
# existing tag at new content and the repository refused. It is not a deployment misfire and
# it is not a race: a pipeline that publishes immutable release tags never re-uses one. A
# success-only rule, which is what the source ships, throws this away - and it is the only
# signal in the set that fires on the ATTEMPT rather than on the preparation.
title: ECR image tag overwrite refused by tag immutability
id: d175ab8d-d4a7-408f-a4bd-97b09e9782d4
name: ecr_tag_overwrite_blocked
status: experimental
description: >-
  A `PutImage` was rejected with `ImageTagAlreadyExistsException`, which ECR returns only
  when a repository configured for tag immutability is asked to repoint an existing tag.
  Treat as an attempted image replacement until the pusher accounts for it.
references:
  - https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutImage.html  # retrieved 2026-08-29
  - https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html  # retrieved 2026-08-29
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
  # `|contains` rather than equality: confirm against a real event whether your trail records
  # the bare exception name or a prefixed form. Prefix-tolerant matching costs nothing here.
  blocked:
    errorCode|contains: 'ImageTagAlreadyExistsException'
  condition: selection and blocked
falsepositives:
  - >-
    A retried push after a network failure, where the first attempt actually succeeded. The
    give-away is a preceding successful `PutImage` for the same repository and tag within
    seconds; a genuine overwrite attempt has no such predecessor.
level: medium
```

The rule fires on the *preparation*, not on the substitution: Sigma has no memory of what
digest a tag previously pointed at, so a `PutImage` carrying an existing tag is
indistinguishable in a single event from one carrying a new tag. The load-bearing complement is
the **digest drift check** in Query 3 — a scheduled comparison of each floating tag's live
`imageDigest` against the digest the build system recorded — which catches the substitution even
when the pipeline role itself is the pusher, the case the principal allowlist exempts.
`detections/kql_t1525.kql` joins each weakening to the pushes that followed it on the same
repository and projects the pushed digests, so an analyst sees content rather than labels.

---

### Key Investigation Queries

> ECR is regional and so are its CloudTrail events — run these in the repository's region, and repeat per region if the registry spans several. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: who weakened which repository, to what, and what was pushed afterwards

```bash
REGION="us-east-1"

RAW=$(for EV in PutImageTagMutability CreateRepository PutImage; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json
done)

if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - lookup-events returned nothing at all for any of the three event"
  echo "    names: a failed call, the wrong region, or a credential without"
  echo "    cloudtrail:LookupEvents. This is NOT 'no repository was weakened'."
else
  # Errors are KEPT. ImageTagAlreadyExistsException is the refusal an immutable repository
  # returns to exactly this attack, and a success-only filter throws it away.
  printf '%s' "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "ecr.amazonaws.com") |
    {weakened_at: .eventTime,
     event: .eventName,
     caller_arn: .userIdentity.arn,
     access_key: .userIdentity.accessKeyId,
     repository: (.requestParameters.repositoryName //
                  .responseElements.repository.repositoryName),
     # PutImageTagMutability: the request parameter is required, so it is authoritative.
     # CreateRepository: the request parameter is ABSENT when the caller omitted it and the
     # repository still defaults to MUTABLE - so fall through to the NESTED response field.
     setting: (.requestParameters.imageTagMutability //
               .responseElements.repository.imageTagMutability),
     filters: (.requestParameters.imageTagMutabilityExclusionFilters // []),
     tag: .requestParameters.imageTag,
     # GROUND TRUTH, nested two levels. There is no flat responseElements.imageDigest.
     digest: .responseElements.image.imageId.imageDigest,
     error: (.errorCode // "SUCCESS"),
     verdict:
       (if ((.errorCode // "") | test("ImageTagAlreadyExistsException")) then "OVERWRITE REFUSED - immutability held; an attempt, not a compromise"
        elif (.errorCode // "") != "" then "CALL FAILED - see error; nothing changed"
        elif .eventName == "PutImage" then "IMAGE PUSHED - reconcile digest against the build system"
        elif ((.requestParameters.imageTagMutability // .responseElements.repository.imageTagMutability) == "IMMUTABLE") then "IMMUTABILITY SET - protective change"
        else "OVERWRITE PERMITTED - existing tags in this repository can now be repointed" end),
     ip: .sourceIPAddress, agent: .userAgent}' | jq -s 'sort_by(.weakened_at)'
fi
```

Read it as a timeline per `repository`. An `OVERWRITE PERMITTED` row followed by an
`IMAGE PUSHED` row on the same repository is the attack, and the interval between them is the
window Query 4 must cover. A non-empty `filters` array on an `IMMUTABLE_WITH_EXCLUSION` row is
the targeted form — read the filter values, because the repository still describes itself as
immutable. `OVERWRITE REFUSED` rows with no preceding `OVERWRITE PERMITTED` mean the control
held; count them separately, as intent. Record `repository`, `caller_arn`, `access_key`,
`weakened_at` and every `digest` as IOCs.

#### Query 2 — Sweep: every repository in the account that can have its tags overwritten

```bash
REGION="us-east-1"

REPOS=$(aws ecr describe-repositories --region "$REGION" --output json)
if [ -z "$REPOS" ]; then
  echo "[!] INCONCLUSIVE - describe-repositories returned nothing. It always returns a"
  echo "    repositories array (possibly empty) when it succeeds, so an empty capture means"
  echo "    the call failed. Fix the credential or region; do not report the account clean."
else
  echo "[i] $(printf '%s' "$REPOS" | jq '.repositories | length') repositories in $REGION"
  # Only IMMUTABLE with no exclusion filters is protected. Every other value permits an
  # existing tag to be repointed, IMMUTABLE_WITH_EXCLUSION included.
  printf '%s' "$REPOS" | jq -r '[.repositories[] |
    {repository: .repositoryName,
     setting: (.imageTagMutability // "MUTABLE (absent - AWS default)"),
     filters: (.imageTagMutabilityExclusionFilters // []),
     scan_on_push: (.imageScanningConfiguration.scanOnPush // false)} |
    select(.setting != "IMMUTABLE" or (.filters | length) > 0)] |
    {overwritable_count: length, overwritable: sort_by(.repository)}'
fi

# Which of those are legitimately mutable because they front a pull-through cache?
PTC=$(aws ecr describe-pull-through-cache-rules --region "$REGION" --output json)
if [ -z "$PTC" ]; then
  echo "[!] INCONCLUSIVE - could not read pull-through cache rules; the legitimate-exception"
  echo "    list is unknown, so treat every mutable repository as unexplained for now."
else
  printf '%s' "$PTC" | jq -r '.pullThroughCacheRules[]? |
    "[i] cache prefix \(.ecrRepositoryPrefix) -> \(.upstreamRegistryUrl) (MUTABLE expected here)"'
fi
```

Every entry in `overwritable` is a repository whose tags can be repointed. Subtract the
pull-through cache prefixes AWS documents as needing `MUTABLE`; whatever remains is a gap to
close, or — if it appears in Query 1's timeline — the incident. The `IMMUTABLE_WITH_EXCLUSION`
rows are counted as overwritable here and would be counted as protected by any check reading
only the headline setting.

#### Query 3 — Inspect: does the live tag still resolve to the digest the build system published?

```bash
REGION="us-east-1"
REPOSITORY="<repository-from-Query-1>"
TAG="<tag-that-consumers-follow>"
KNOWN_GOOD_DIGEST="<sha256-digest-from-your-build-system>"

IMG=$(aws ecr describe-images --repository-name "$REPOSITORY" \
        --image-ids imageTag="$TAG" --region "$REGION" --output json)
if [ -z "$IMG" ]; then
  echo "[!] INCONCLUSIVE - describe-images returned nothing for $REPOSITORY:$TAG. Either the"
  echo "    tag does not exist (ImageNotFoundException) or the call failed. Distinguish the"
  echo "    two before concluding anything; an absent tag is itself a finding."
else
  LIVE_DIGEST=$(printf '%s' "$IMG" | jq -r '.imageDetails[0].imageDigest // empty')
  PUSHED_AT=$(printf '%s' "$IMG" | jq -r '.imageDetails[0].imagePushedAt // "unknown"')
  LAST_PULL=$(printf '%s' "$IMG" | jq -r '.imageDetails[0].lastRecordedPullTime // "never recorded"')
  if [ -z "$LIVE_DIGEST" ]; then
    echo "[!] INCONCLUSIVE - the response carried no imageDigest; inspect the raw output."
  elif [ "$LIVE_DIGEST" = "$KNOWN_GOOD_DIGEST" ]; then
    echo "[OK] $REPOSITORY:$TAG resolves to the known-good digest $LIVE_DIGEST"
    echo "     pushed_at=$PUSHED_AT last_recorded_pull=$LAST_PULL"
  else
    echo "[FAIL] DIGEST DRIFT on $REPOSITORY:$TAG"
    echo "       live  = $LIVE_DIGEST   (pushed_at=$PUSHED_AT)"
    echo "       known = $KNOWN_GOOD_DIGEST"
    echo "       last_recorded_pull=$LAST_PULL - anything that pulled after $PUSHED_AT"
    echo "       received the live digest."
  fi
fi

# The whole repository in push order, so the substitution reads as a sequence rather than a
# single value. `<untagged>` entries are what a repointed tag leaves behind.
ALL=$(aws ecr describe-images --repository-name "$REPOSITORY" --region "$REGION" --output json)
[ -z "$ALL" ] && echo "[!] INCONCLUSIVE - could not enumerate the repository's images."
printf '%s' "$ALL" | jq -r '.imageDetails | sort_by(.imagePushedAt) | .[] |
  {digest: .imageDigest, tags: (.imageTags // ["<untagged>"]), pushed: .imagePushedAt,
   last_pull: (.lastRecordedPullTime // "never recorded")}'
```

The assertion is on the **digest**, not the tag: a tag that still exists proves nothing,
because repointing it is the attack. `[FAIL] DIGEST DRIFT` is the confirmed substitution, and
`imagePushedAt` on that digest opens the exposure window. In the listing, an `<untagged>` image
pushed shortly *before* the current tagged one is usually the legitimate build the overwrite
displaced — preserve it; it is both evidence and the rollback target. `lastRecordedPullTime` is
coarse (one timestamp per image, no count and no principal) but a value later than the drift
confirms something consumed the substituted content.

#### Query 4 — The exposure window: what pulled the tag, and which workloads reference it

```bash
REGION="us-east-1"
REPOSITORY="<repository-from-Query-1>"
WEAKENED_AT="<weakened-at-from-Query-1>"

# Pulls ARE in CloudTrail - ECR has no data-event category, so these are management events,
# captured by default. What they do NOT carry is the digest served: AWS's published pull event
# records requestParameters.imageIds[].imageTag and "responseElements": null. This establishes
# WHEN and BY WHOM the tag was pulled, never WHICH CONTENT came back.
PULLS=$(for EV in BatchGetImage GetDownloadUrlForLayer; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$WEAKENED_AT" \
    --region "$REGION" --output json
done)

if [ -z "$PULLS" ]; then
  echo "[!] INCONCLUSIVE - no pull events returned. Check the trail's ReadWriteType before"
  echo "    reading this as 'nothing pulled it': a trail created WriteOnly drops both of"
  echo "    these read events entirely and produces exactly this empty result."
  aws cloudtrail describe-trails --region "$REGION" \
    --query 'trailList[].{Name:Name,Multi:IsMultiRegionTrail}' --output table
else
  printf '%s' "$PULLS" | jq -r --arg repo "$REPOSITORY" '
    .Events[].CloudTrailEvent | fromjson |
    select(.eventSource == "ecr.amazonaws.com") |
    select(.requestParameters.repositoryName == $repo) |
    {time: .eventTime, event: .eventName, puller: .userIdentity.arn,
     tags_requested: [ (.requestParameters.imageIds // [])[] | .imageTag // "by-digest" ],
     layer: .requestParameters.layerDigest,
     ip: .sourceIPAddress, agent: .userAgent}' | \
  jq -s 'group_by(.puller) | map({puller: .[0].puller, pulls: length,
          first: (map(.time) | min), last: (map(.time) | max),
          tags_requested: (map(.tags_requested[]?) | unique),
          agents: (map(.agent) | unique)})'
fi
```

A puller whose `tags_requested` contains `by-digest` pinned the image and is unaffected. A
puller that named the tag received whatever the tag pointed at *at that moment*, and if `first`
is later than `WEAKENED_AT` you must assume that was the substituted digest — no field will
tell you otherwise. The honest incident record reads "N principals pulled by tag inside the
window; the content each received is not recoverable from the log".

```bash
REGION="us-east-1"; REPOSITORY="<repository-from-Query-1>"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REPO_URI="${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/${REPOSITORY}"

# Consumer inventory: which workloads reference this repository, and by tag or by digest?
# A reference containing "@sha256:" is pinned and unreachable by tag repointing.
TDS=$(aws ecs list-task-definitions --region "$REGION" --query 'taskDefinitionArns[]' --output text)
if [ -z "$TDS" ]; then
  echo "[!] INCONCLUSIVE - no ECS task definitions returned; ECS coverage unknown, not clean"
else
  for TD in $TDS; do
    aws ecs describe-task-definition --task-definition "$TD" --region "$REGION" \
      --query 'taskDefinition.containerDefinitions[].image' --output text | \
      grep -F "$REPO_URI" | sed "s|^|  ECS $TD -> |"
  done
fi
FNS=$(aws lambda list-functions --region "$REGION" --output json)
[ -z "$FNS" ] && echo "[!] INCONCLUSIVE - no Lambda listing; Lambda coverage unknown, not clean"
for FN in $(printf '%s' "$FNS" | jq -r '.Functions[] | select(.PackageType=="Image") | .FunctionName'); do
  aws lambda get-function --function-name "$FN" --region "$REGION" --query 'Code.ImageUri' \
    --output text | grep -F "$REPO_URI" | sed "s|^|  LAMBDA $FN -> |"
done
echo "[i] EKS is not in the AWS API - enumerate with:"
echo "    kubectl get pods -A -o jsonpath='{..image}' | tr ' ' '\\n' | grep -F $REPO_URI"
```

Any reference without `@sha256:` re-resolves on every task placement, pod restart and cold
start, so those workloads keep pulling whatever the tag points at until you fix the tag or the
reference. Pinned references are unaffected and should not be redeployed in a panic.

#### Query 5 — Full session reconstruction of the principal that weakened the setting

```bash
REGION="us-east-1"; ACCESS_KEY_ID="<access-key-from-Query-1>"

RAW=$(aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json)
if [ -z "$RAW" ]; then
  echo "[!] INCONCLUSIVE - no events for that access key. Confirm the key id and the region:"
  echo "    an assumed-role session key is only visible in the regions it operated in."
else
  printf '%s' "$RAW" | jq -r '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     resource: (.requestParameters.repositoryName // .requestParameters.roleName //
                .requestParameters.userName // ""),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | jq -s 'sort_by(.time)'
fi
```

Look for the rest of the campaign: other repositories weakened, `SetRepositoryPolicy` opening
cross-account push (`../ecr.privilege-escalation.repository-policy-applied/`),
`PutImageScanningConfiguration` or `PutRegistryScanningConfiguration` turning scanning off
(`../ecr.stealth.image-scanning-disabled/`), `PutLifecyclePolicy` staging delayed
deletion (the lifecycle-policy use case (not in this set)), and IAM changes. Remediate
each with its own playbook.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

**The ordering is load-bearing and the obvious order is wrong.** The instinct is to set
`IMMUTABLE` first. Do not: once the repository is immutable, a `PutImage` carrying the existing
tag is refused with `ImageTagAlreadyExistsException`, so the tag can no longer be repointed at
the known-good digest and stays poisoned until deleted outright. Capture evidence, repair the
tag while the repository is still writable, then close the setting. Deleting the malicious
digest is safe at any point — immutability constrains `PutImage`, not `BatchDeleteImage` — but
it destroys the manifest, so do it after Step 1.

> Run every command under the **break-glass responder credentials** from §1, not under any
> principal being contained and not under the CI/CD role.

#### Step 1 — Freeze the evidence before you change anything

```bash
REGION="us-east-1"; REPOSITORY="<repository-from-Query-1>"
OUT="./ecr-evidence-${REPOSITORY//\//_}.json"

REPO_CFG=$(aws ecr describe-repositories --repository-names "$REPOSITORY" --region "$REGION" --output json)
IMAGES=$(aws ecr describe-images --repository-name "$REPOSITORY" --region "$REGION" --output json)
if [ -z "$REPO_CFG" ] || [ -z "$IMAGES" ]; then
  echo "[!] INCONCLUSIVE - one or both reads returned nothing; evidence capture is INCOMPLETE."
  echo "    Fix the credential or region and re-run BEFORE touching the repository: every"
  echo "    later step in this section destroys part of what these two calls record."
else
  printf '{"repository":%s,"images":%s}\n' "$REPO_CFG" "$IMAGES" > "$OUT"
  echo "[OK] tag-to-digest mapping and repository configuration written to $OUT"
fi

# Copy the suspect manifest out - it is the artefact, and Step 3 deletes it. batch-get-image
# takes the DIGEST, so pin it rather than naming the tag the attacker controls.
SUSPECT_DIGEST="<malicious-digest-from-Query-3>"
MAN=$(aws ecr batch-get-image --repository-name "$REPOSITORY" \
        --image-ids imageDigest="$SUSPECT_DIGEST" \
        --accepted-media-types "application/vnd.docker.distribution.manifest.v2+json" \
                               "application/vnd.oci.image.manifest.v1+json" \
        --region "$REGION" --output json)
DOC=$(printf '%s' "$MAN" | jq -r '.images[0].imageManifest // empty')
if [ -z "$DOC" ]; then
  echo "[!] INCONCLUSIVE - could not retrieve the suspect manifest; preserve the repository"
  echo "    as-is and escalate rather than proceeding to deletion."
else
  printf '%s' "$DOC" > "./manifest-${SUSPECT_DIGEST#sha256:}.json"
  echo "[OK] suspect manifest preserved; layer digests:"
  printf '%s' "$DOC" | jq -r '.layers[]?.digest'
fi
```

#### Step 2 — Repoint the tag at the known-good digest (BEFORE re-imposing immutability)

```bash
REGION="us-east-1"; REPOSITORY="<repository-from-Query-1>"
TAG="<tag-that-consumers-follow>"
KNOWN_GOOD_DIGEST="<sha256-digest-from-your-build-system>"

# Re-tagging is a PutImage of the KNOWN-GOOD manifest under the existing tag, and it requires
# the repository to still permit overwrite - which is why this precedes Step 4.
GOOD=$(aws ecr batch-get-image --repository-name "$REPOSITORY" \
         --image-ids imageDigest="$KNOWN_GOOD_DIGEST" \
         --accepted-media-types "application/vnd.docker.distribution.manifest.v2+json" \
                                "application/vnd.oci.image.manifest.v1+json" \
         --region "$REGION" --output json)
GOOD_MANIFEST=$(printf '%s' "$GOOD" | jq -r '.images[0].imageManifest // empty')
if [ -z "$GOOD_MANIFEST" ]; then
  echo "[!] INCONCLUSIVE - the known-good digest is not in this repository, so the tag cannot"
  echo "    be repointed from here. Rebuild and push from trusted source, and do NOT set"
  echo "    IMMUTABLE until the tag carries content you trust."
else
  aws ecr put-image --repository-name "$REPOSITORY" --image-tag "$TAG" \
    --image-manifest "$GOOD_MANIFEST" --region "$REGION" --output json > /dev/null
  NOW=$(aws ecr describe-images --repository-name "$REPOSITORY" --image-ids imageTag="$TAG" \
          --region "$REGION" --query 'imageDetails[0].imageDigest' --output text)
  [ "$NOW" = "$KNOWN_GOOD_DIGEST" ] \
    && echo "[OK] $REPOSITORY:$TAG now resolves to the known-good digest" \
    || echo "[FAIL] $REPOSITORY:$TAG still resolves to $NOW - repointing did not take effect"
fi
```

#### Step 3 — Delete the substituted image by digest

```bash
REGION="us-east-1"; REPOSITORY="<repository-from-Query-1>"
SUSPECT_DIGEST="<malicious-digest-from-Query-3>"

# Deleting BY DIGEST removes the image and all of its tags; deleting by tag would only detach
# the label and leave the content pullable by digest. Step 1 preserved the manifest.
RES=$(aws ecr batch-delete-image --repository-name "$REPOSITORY" \
        --image-ids imageDigest="$SUSPECT_DIGEST" --region "$REGION" --output json)
# batch-delete-image returns HTTP 200 with a populated failures[] on partial failure, so
# "no errorCode" is not success here. Read both arrays.
DELETED=$(printf '%s' "$RES" | jq '[.imageIds[]? | select(.imageDigest != null)] | length')
FAILED=$(printf '%s' "$RES" | jq '.failures | length')
if [ -z "$RES" ]; then
  echo "[!] INCONCLUSIVE - batch-delete-image returned nothing; the image may still be live."
elif [ "${DELETED:-0}" -ge 1 ] && [ "${FAILED:-0}" -eq 0 ]; then
  echo "[OK] removed $DELETED image reference(s) for $SUSPECT_DIGEST"
else
  echo "[FAIL] deleted=${DELETED:-0} failures=${FAILED:-0}"
  printf '%s' "$RES" | jq -r '.failures[]? | "  \(.failureCode): \(.failureReason)"'
fi
```

#### Step 4 — Re-impose tag immutability, with no exclusions

```bash
REGION="us-east-1"; REPOSITORY="<repository-from-Query-1>"

# IMMUTABLE with no exclusion filters. Anything else leaves a writable tag namespace, and
# IMMUTABLE_WITH_EXCLUSION would restore exactly the state being remediated.
aws ecr put-image-tag-mutability --repository-name "$REPOSITORY" \
  --image-tag-mutability IMMUTABLE --region "$REGION" --output json > /dev/null
SET=$(aws ecr describe-repositories --repository-names "$REPOSITORY" --region "$REGION" \
        --query 'repositories[0].imageTagMutability' --output text)
if [ -z "$SET" ]; then echo "[!] INCONCLUSIVE - could not read the setting back; unconfirmed."
elif [ "$SET" = "IMMUTABLE" ]; then echo "[OK] $REPOSITORY is IMMUTABLE - tags can no longer be repointed"
else echo "[FAIL] $REPOSITORY reports $SET - tags remain overwritable"; fi
```

> This is a **breaking change for the pipeline** that publishes floating tags: a build that
> re-pushes `:latest` will now fail with `ImageTagAlreadyExistsException`. That is the correct
> end state — pipelines should publish immutable, uniquely named tags and move a *deployment
> pointer*, not a registry tag — but say it out loud in the incident channel before the first
> failed build becomes a second incident.

#### Step 5 — Contain the principal that weakened the setting

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
DENY='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["ecr:PutImageTagMutability","ecr:PutImage","ecr:BatchDeleteImage","ecr:SetRepositoryPolicy","ecr:CreateRepository"],"Resource":"*"}]}'
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')      # user ARN: name is the LAST segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive
    echo "[OK] disabled key $K for $U"
  done
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenyEcrWrite" \
    --policy-document "$DENY"
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')       # role ARN: name is the 2ND segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenyEcrWrite" \
    --policy-document "$DENY"
  echo "[OK] revoked pre-$CUTOFF sessions and denied ECR writes for role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed role - root, federated or a"
  echo "    service principal. Contain manually; neither branch above applies."
fi
```

> `aws:TokenIssueTime` revokes only sessions issued **before** the cutoff. A credential
> re-fetched after the policy lands gets a newer issue time and is not denied — the
> `EmergencyDenyEcrWrite` statement, not the revocation, is what holds the line against a
> still-live source of credentials.

---

## 4. Eradication

### Remove Attacker Access

#### Confirm every overwritable repository is accounted for, and rebuild where the digest is doubtful

Re-run Query 2. Each entry in `overwritable` is a pull-through cache prefix (AWS documents
`MUTABLE` as required there), a repository with a written exception, or a gap — set `IMMUTABLE`
on the third category, and read the `IMMUTABLE_WITH_EXCLUSION` rows closely, because a control
that inspects only the headline setting reports those as protected. Step 2 repointed the tag at
a digest already in the repository; if Query 1 shows more than one push in the window, or the
pipeline role is itself implicated, that digest is not trustworthy either. Rebuild from source,
push a uniquely named immutable tag and move the deployment reference to it. Treating "the
previous digest" as clean by default is the same mistake as restoring a Lambda function from
the attacker's own downloaded copy.

#### Repoint consumers at digests, and treat the execution roles  of what pulled as compromised

From Query 4's inventory, every reference lacking `@sha256:` re-resolves on each placement —
change them to digest references in the ECS task definitions, EKS manifests, Lambda `ImageUri`
values and App Runner services, so a future repointing cannot reach a running workload at all.
That is the structural fix; immutability is only the registry-side half. Everything that pulled
by tag between `weakened_at` and the repair ran attacker-supplied code under its own execution
role: rotate every secret those roles could read and revoke their sessions, scoping by the
repository's consumer list rather than by observed pulls where the pull inventory is
incomplete — the honest default, given the blind spot. Then right-size configuration rights:
`ecr:PutImageTagMutability`, `ecr:CreateRepository` and `ecr:SetRepositoryPolicy` belong to the
pipeline that owns repository lifecycle, not to workload roles or developers — review them for
every principal Query 1 and Query 5 surfaced.

#### Remove the emergency policies once clean, and assert it

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
if echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}'); K=role
  for P in EmergencyDenyEcrWrite EmergencyRevokeSessions; do
    aws iam delete-role-policy --role-name "$N" --policy-name "$P"; done
  LEFT=$(aws iam list-role-policies --role-name "$N" --query 'PolicyNames[]' --output text)
elif echo "$SUSPECT_ARN" | grep -q ":user/"; then
  N=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}'); K=user
  aws iam delete-user-policy --user-name "$N" --policy-name "EmergencyDenyEcrWrite"
  LEFT=$(aws iam list-user-policies --user-name "$N" --query 'PolicyNames[]' --output text)
else K=none; LEFT=""; fi
case "$K:$LEFT" in
  none:*)      echo "[!] INCONCLUSIVE - neither user nor role; check manually";;
  *Emergency*) echo "[FAIL] an emergency policy is still attached: $LEFT";;
  *)           echo "[OK] no emergency policy remains on $N";;
esac
```

---

## 5. Recovery

### Restore Clean State

#### Verify the tag resolves to the known-good DIGEST — not that the tag exists

```bash
REGION="us-east-1"; REPOSITORY="<repository-from-Query-1>"
TAG="<tag-that-consumers-follow>"
KNOWN_GOOD_DIGEST="<sha256-digest-from-your-build-system>"

# The assertion is on the digest. A check that confirms the TAG is present proves nothing at
# all here: repointing that tag is the entire technique, so tag presence is true both before
# and after the attack.
RESP=$(aws ecr describe-images --repository-name "$REPOSITORY" --image-ids imageTag="$TAG" \
         --region "$REGION" --output json)
LIVE=$(printf '%s' "$RESP" | jq -r '.imageDetails[0].imageDigest // empty')
if [ -z "$RESP" ] || [ -z "$LIVE" ]; then
  echo "[!] INCONCLUSIVE - no imageDigest came back for $REPOSITORY:$TAG. The tag may be"
  echo "    absent, or the call failed. Either way this is not a pass."
elif [ "$LIVE" = "$KNOWN_GOOD_DIGEST" ]; then
  echo "[OK] $REPOSITORY:$TAG -> $LIVE matches the known-good digest"
else
  echo "[FAIL] $REPOSITORY:$TAG -> $LIVE, expected $KNOWN_GOOD_DIGEST"
fi
```

#### Verify the substituted digest is gone from the repository

```bash
REGION="us-east-1"; REPOSITORY="<repository-from-Query-1>"
SUSPECT_DIGEST="<malicious-digest-from-Query-3>"

ALL=$(aws ecr describe-images --repository-name "$REPOSITORY" --region "$REGION" --output json)
if [ -z "$ALL" ]; then
  echo "[!] INCONCLUSIVE - could not enumerate images; the suspect digest is unaccounted for."
else
  HIT=$(printf '%s' "$ALL" | jq --arg d "$SUSPECT_DIGEST" \
          '[.imageDetails[] | select(.imageDigest == $d)] | length')
  [ "${HIT:-0}" -eq 0 ] \
    && echo "[OK] $SUSPECT_DIGEST is absent from $REPOSITORY" \
    || echo "[FAIL] $SUSPECT_DIGEST is still present and remains pullable by digest"
fi
```

#### Verify immutability holds, with no exclusion filters

```bash
REGION="us-east-1"; REPOSITORY="<repository-from-Query-1>"

# Both halves must hold. IMMUTABLE_WITH_EXCLUSION, or IMMUTABLE carrying filters, leaves the
# named tags writable while the headline value reads as protected.
CFG=$(aws ecr describe-repositories --repository-names "$REPOSITORY" --region "$REGION" --output json)
SETTING=$(printf '%s' "$CFG" | jq -r '.repositories[0].imageTagMutability // empty')
NFILT=$(printf '%s' "$CFG" | jq '.repositories[0].imageTagMutabilityExclusionFilters // [] | length')
if [ -z "$CFG" ] || [ -z "$SETTING" ]; then
  echo "[!] INCONCLUSIVE - no imageTagMutability came back; the setting is unverified, not clean."
elif [ "$SETTING" = "IMMUTABLE" ] && [ "${NFILT:-0}" -eq 0 ]; then
  echo "[OK] $REPOSITORY is IMMUTABLE with no exclusion filters"
else
  echo "[FAIL] $REPOSITORY reports $SETTING with ${NFILT:-0} exclusion filter(s)"
  printf '%s' "$CFG" | jq -r '.repositories[0].imageTagMutabilityExclusionFilters[]? |
    "       \(.filterType)=\(.filter)"'
fi
```

#### Verify the contained principal can no longer weaken a repository

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
REGION="us-east-1"; REPOSITORY="<repository-from-Query-1>"

REPO_ARN=$(aws ecr describe-repositories --repository-names "$REPOSITORY" --region "$REGION" \
             --query 'repositories[0].repositoryArn' --output text)
# "No further PutImageTagMutability events" is not an assertion - a contained principal emits
# nothing, and silence would print [OK] for a broken containment as readily as a working one.
# Ask IAM for the decision directly instead.
SIM=$(aws iam simulate-principal-policy --policy-source-arn "$SUSPECT_ARN" \
        --action-names ecr:PutImageTagMutability ecr:PutImage \
        --resource-arns "$REPO_ARN" --output json)
if [ -z "$SIM" ]; then
  echo "[!] INCONCLUSIVE - the simulation call failed; containment is unverified, not confirmed."
  echo "    (simulate-principal-policy needs an IAM user or role ARN, not an assumed-role ARN:"
  echo "     convert arn:aws:sts::ACCT:assumed-role/ROLE/SESSION to arn:aws:iam::ACCT:role/ROLE.)"
else
  ALLOWED=$(printf '%s' "$SIM" | jq -r '[.EvaluationResults[]
              | select(.EvalDecision != "explicitDeny" and .EvalDecision != "implicitDeny")
              | .EvalActionName] | join(", ")')
  if [ -n "$ALLOWED" ]; then echo "[FAIL] $SUSPECT_ARN is still permitted: $ALLOWED"
  else echo "[OK] both ecr:PutImageTagMutability and ecr:PutImage are denied for $SUSPECT_ARN"; fi
fi
```

#### Confirm the corrected detection fires

```bash
echo "MUST fire on:     PutImageTagMutability / ecr.amazonaws.com / no errorCode with"
echo "  requestParameters.imageTagMutability = MUTABLE, MUTABLE_WITH_EXCLUSION or"
echo "  IMMUTABLE_WITH_EXCLUSION. The carve-out rule must additionally fire when"
echo "  requestParameters.imageTagMutabilityExclusionFilters carries filter=latest, and the"
echo "  correlation must fire when a PutImage on the SAME requestParameters.repositoryName"
echo "  follows the weakening inside thirty minutes."
echo "MUST NOT fire on: PutImageTagMutability setting IMMUTABLE with no exclusion filters -"
echo "  the protective change, and firing on it inverts the rule; nor on a PutImage refused"
echo "  with ImageTagAlreadyExistsException, which belongs to the medium attempt rule."
echo "EXPECTED FP, by design: repositories fronting a pull-through cache rule, which AWS"
echo "  documents as needing MUTABLE. Exclude those by repository NAME - never by principal,"
echo "  because the principal that maintains the cache is the one an actor would borrow."
```

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A repository's tag namespace could be re-opened by a single API call | `ecr:PutImageTagMutability` was reachable outside the pipeline that owns repository configuration; no SCP constrained it |
| The weakening was not noticed, and the substitution could not be proved | The shipped rule matched one of four documented values on one of two paths at P4; no known-good digest baseline existed to compare the live digest against |
| Consumers followed a floating tag | Deployment definitions referenced `:latest` rather than `@sha256:`, so every placement re-resolved the pointer the attacker controlled |
| Which workloads ran the substituted image is unknown | The pull events record the tag requested, not the digest served — a structural property of the log, not a configuration gap |
| An `IMMUTABLE_WITH_EXCLUSION` repository would have passed a compliance check | Controls read the headline `imageTagMutability` value and never inspected `imageTagMutabilityExclusionFilters` |

### Recommended Guardrails

**Deny the weakening outright, and let the API enforce it**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
// StringNotLike, never StringNotEquals - the value carries a wildcard, and with Deny the
// wrong operator fails CLOSED: StringNotEquals against a wildcarded ARN matches every
// principal including the pipeline, denying the action to everybody and causing an outage.
{
  "Effect": "Deny",
  "Action": ["ecr:PutImageTagMutability"],
  "Resource": "*",
  "Condition": {
    "StringNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] }
  }
}
```

**Make the safe state the default at creation.** `CreateRepository` defaults to `MUTABLE` when
the parameter is omitted, so denying non-`IMMUTABLE` *values* does not cover the omitted-value
path. Set `IMMUTABLE` as the default in a repository creation template
(`ecr:CreateRepositoryCreationTemplate`) so the omission lands safe, and treat any
condition-key-based deny as unverified until you confirm the key is published in the ECR
service-authorization reference — IAM accepts an unknown condition key silently, so a `Deny`
whose condition never matches is a no-op that reads as protection.

**Structural controls**
- **Reference images by digest everywhere** — `@sha256:` in ECS task definitions, EKS manifests,
  Lambda `ImageUri` and App Runner services. A pinned consumer cannot be reached by tag
  repointing at all, which converts this technique from a compromise into an alert
- **Publish immutable, uniquely named tags** (build id, commit sha) and move a deployment
  pointer rather than a registry tag — remove the re-resolution and the floating tag stops
  being a control surface
- **Adopt ECR image signing** and verify signatures at admission (`aws ecr
  put-signing-configuration` / `describe-image-signing-status`, with an admission controller on
  the consumer side). Confirm the current capability and its regional availability against the
  ECR documentation before designing around it — this is the registry analogue of Lambda code
  signing, and it is the only control that survives a compromised pipeline
- **Record the digest of every published tag in the CMDB** at build time. Without it, §5's
  assertions have nothing to assert against
- **Treat `imageTagMutabilityExclusionFilters` as part of the setting.** Any control, dashboard
  or Config rule that reads `imageTagMutability` alone will call an
  `IMMUTABLE_WITH_EXCLUSION` repository compliant

**Detection improvements**
- Deploy all six documents in `detections/sigma_t1525.yml`, not the single-value name match
- Run the Query-3 digest drift check on a schedule for every floating tag — it is the only
  signal that fires when the pipeline role itself is the pusher
- Alert on `ImageTagAlreadyExistsException`; it is free, it has one cause, and it is the only
  event in the set that reports an attempt rather than a preparation
- Alert on the appearance of *any* `imageTagMutabilityExclusionFilters` entry, then allowlist
  the ones you meant

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1525 — Implant Internal Image (primary, Persistence TA0003); T1685 — Disable or Modify Tools (secondary, Defense Impairment TA0112) |
| Primary API | `ecr:PutImageTagMutability` (or `ecr:CreateRepository`) → `ecr:InitiateLayerUpload` → `ecr:UploadLayerPart` → `ecr:CompleteLayerUpload` → `ecr:PutImage` carrying the existing tag |
| Event source | `ecr.amazonaws.com`, **management** plane, regional. ECR has **no** CloudTrail data-event category — `AWS::ECR::Repository` is absent from the supported data-event resource types — so pulls and pushes are management events, on by default, and there is nothing to enable |
| Key discriminator | The **value** `imageTagMutability` lands on. Three of the four documented values — `MUTABLE`, `MUTABLE_WITH_EXCLUSION`, `IMMUTABLE_WITH_EXCLUSION` — permit overwrite; only `IMMUTABLE` with no exclusion filters does not |
| Ground-truth signal | `imageDigest` — the sha256 of the manifest. In the event: `responseElements.image.imageId.imageDigest` (nested **two** levels; there is no flat form). Live: `imageDetails[].imageDigest` from `describe-images`. Drift from the build system's recorded digest is the confirmed substitution; **tag presence proves nothing, because repointing the tag is the technique** |
| Field-shape traps | `CreateRepository` omits `requestParameters.imageTagMutability` on the default path and the repository is still `MUTABLE` — use `responseElements.repository.imageTagMutability`. `imageTagMutabilityExclusionFilters` is an array of `{filter, filterType}` objects, so `|contains` reaches the values only on a backend that serialises the array |
| "Was it used" pivot | `BatchGetImage` / `GetDownloadUrlForLayer` after the overwrite timestamp — **management events, present by default**, but AWS's published pull event carries `requestParameters.imageIds[].imageTag` and `"responseElements": null`, so they establish *when* and *by whom*, never *which digest was served*. `lastRecordedPullTime` on the image is one coarse timestamp with no principal |
| Blast radius | Every ECS task, EKS pod, Lambda container function and App Runner service that pulls the repointed tag, each running attacker code under its own execution role. Not in the event — it must be assembled from the consuming services (Query 4) |
| Error strings | `PutImage`: `ImageAlreadyExistsException` (benign re-push), **`ImageTagAlreadyExistsException`** (overwrite refused by immutability — the attack signal), `ImageDigestDoesNotMatchException`, `LayersNotFoundException`, `ReferencedImagesNotFoundException`, `LimitExceededException`, `InvalidParameterException`, `KmsException`, `RepositoryNotFoundException`, `ServerException`. `PutImageTagMutability`: `InvalidParameterException`, `RepositoryNotFoundException`, `ServerException`. Denials: `AccessDeniedException` (403) and `NotAuthorized` (401) are documented; bare `AccessDenied` is widely observed but not in ECR's documented set — match all three |
| Reversibility | The setting reverses in one call; the substitution does not. Re-imposing `IMMUTABLE` **before** repointing the tag makes the tag unwritable and blocks the repair (§3) |

**MITRE mapping note.** The source maps **T1578 / TA0005** — *Modify Cloud Compute
Infrastructure*, which covers instances, snapshots, VM images and backups. Relaxing a
container registry's tag-integrity setting is not that, so the mapping is wrong on the merits
even though the ID resolves. **T1525 — Implant Internal Image** is the corrected primary:
MITRE describes it as implanting a modified image into an environment's image repository so
that it is deployed by ordinary means, which is exactly what a repointed tag achieves. It is a stretch in that tag
immutability is a setting rather than a security product; a deployer uncomfortable with it
should drop the second tag rather than substitute a revoked identifier. The directory's
`stealth` segment tracks TA0005 (Stealth, formerly Defense Evasion), the tactic the source
labelled.

### Residual Risk

**Which workloads ran the substituted image cannot be established from the log.** The pull
events are present — ECR has no data-event category, so nothing was missing — but they record
the tag requested, not the digest returned. Every consumer that pulled by tag between the
overwrite and the repair must be treated as having received the malicious content, and the
incident record has to say that as a bounded assumption rather than a measurement.

**Anything already pulled is already local**, and **the execution roles stay compromised until
rotated.** A node, task or function that cached the image keeps running it until it is
replaced; deleting the digest removes the source, not the copies, so force a rollout of every
consumer rather than reading "the digest is gone from ECR" as "the code is no longer running".
The substituted image ran under each consumer's own role, so every credential it could reach —
Secrets Manager values, SSM parameters, database rows, S3 objects, further ECR pushes — must be
assumed read. Setting `IMMUTABLE` does nothing about that.

**Immutability protects the tag namespace, not the content.** An actor who can still call
`ecr:PutImage` can publish a *new* tag, and a deployment reference later moved to it reproduces
the compromise by another route; digest-pinned consumers and signature verification at
admission are what close that. **Pull-through cache repositories stay mutable by design** and
carry the upstream registry's integrity guarantee, not yours.
