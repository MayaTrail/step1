# Detection Note — T1525 / T1685 (ECR Image Tag Overwrite Enabled)

**Signal:** a repository's `imageTagMutability` moved to a value that permits an existing tag
to be repointed at a new digest — `MUTABLE`, `MUTABLE_WITH_EXCLUSION`, or
`IMMUTABLE_WITH_EXCLUSION` with a filter naming a floating production tag — set either by
`PutImageTagMutability` or at `CreateRepository`; and, separately, a `PutImage` refused with
`ImageTagAlreadyExistsException`.

**The tag is a pointer; the digest is the content.** An ECR image is identified by
`imageDigest`, the sha256 of its manifest. A tag is a mutable label attached to a digest.
When a repository permits overwrite, a `PutImage` carrying an existing tag repoints that
label at new content, and **nothing else about the repository changes** — same name, same
ARN, same URI, same repository policy, same encryption, same scanning configuration, same
lifecycle policy. The reference every consumer holds still resolves. This is the registry
form of the Lambda code-overwrite technique, and
`imageDigest` plays the part `CodeSha256` plays there: it is the only field that moves, and
any "was this replaced" question is answered by digest drift, never by the presence of a tag.

**What the original rule got wrong** — it matches
`eventName:"PutImageTagMutability" AND requestParameters.imageTagMutability:"mutable"` with a
success filter and a single hard-coded principal exclusion. Four defects follow, and each one
is a silent false negative rather than noise:

1. **Two of the three overwrite-permitting values are missed.** AWS documents the valid
   values as `MUTABLE | IMMUTABLE | IMMUTABLE_WITH_EXCLUSION | MUTABLE_WITH_EXCLUSION`.
   Overwrite is possible under three of them.
2. **The `CreateRepository` path is missed entirely.** Mutability is a `CreateRepository`
   parameter as well as a `PutImageTagMutability` one.
3. **The default is missed.** AWS: *"If this parameter is omitted, the default setting of
   `MUTABLE` will be used which will allow image tags to be overwritten."* On the ordinary
   creation path `requestParameters.imageTagMutability` is **absent**, so a rule reading the
   request parameter sees `null` and stays silent over a repository that is overwritable.
4. **`ImageTagAlreadyExistsException` is discarded** by the success filter. That error has one
   cause and it is the attempted attack.

## The exclusion filters are the sharp end

Tag mutability is no longer a two-state setting. `imageTagMutabilityExclusionFilters` is an
array of one to five `{filter, filterType}` objects, `filterType` being `WILDCARD`, and it
inverts the headline setting for the tags it names:

| Setting | Which tags can be overwritten |
|---------|-------------------------------|
| `MUTABLE` | all of them |
| `IMMUTABLE` | none |
| `MUTABLE_WITH_EXCLUSION` | all except the filtered ones |
| `IMMUTABLE_WITH_EXCLUSION` | **only** the filtered ones |

`IMMUTABLE_WITH_EXCLUSION` is the quiet one. The repository's `imageTagMutability` still reads
as an immutable variant, so a compliance check or dashboard that inspects only that field
reports the repository as protected. AWS's own CLI example for the setting is
`--image-tag-mutability IMMUTABLE_WITH_EXCLUSION --image-tag-mutability-exclusion-filters
filterType=WILDCARD,filter=latest` — "everything immutable except the one tag production
follows". `ecr_tag_mutability_carveout` exists for exactly that shape.

**Field-shape warning.** `imageTagMutabilityExclusionFilters` is an array of objects. Whether
a Sigma `|contains` reaches the `filter` values depends on how your pipeline flattens the
array — a backend that serialises it to a string matches, one that explodes it into
`...ExclusionFilters.0.filter` does not. Confirm against a real event; treat
`ecr_tag_mutability_weakened` as the load-bearing rule and the carve-out rule as the
sharpener.

## ECR has no data events — and that cuts both ways

**ECR is absent from CloudTrail's supported data-event resource types.** There is no
`AWS::ECR::Repository` entry, so there is no ECR data-event category to enable and no
advanced event selector to write. AWS states that CloudTrail captures *"All API calls,
including calls from the Amazon ECR console"*, and that *"All Amazon ECR API actions are
logged by CloudTrail"*. Recent ECR examples carry `"managementEvent": true` and
`"eventCategory": "Management"` explicitly.

So `BatchGetImage` and `GetDownloadUrlForLayer` — the actual pull path — **are management
events and are visible by default**. Do not repeat the reflex that they must be data-plane;
this is rule A2's failure mode, and here it would send a responder to enable a data-event
category that does not exist while telling them the pull evidence is unobtainable.

**But the pull events do not carry the digest.** AWS's published `BatchGetImage` CloudTrail
example records `"responseElements": null` and `requestParameters.imageIds[].imageTag`. The
log shows the **tag the client asked for**, never the **digest the registry served**. That is
the structural blind spot: after an overwrite, a `BatchGetImage` for `:latest` at 14:02 is
indistinguishable in the log from the same call the day before, and the only thing separating
"pulled the clean image" from "pulled the malicious one" is whether the timestamp falls after
the overwrite. Everything pulled in that window must be assumed compromised.

Two further caveats on the pull evidence:

- A trail configured with `ReadWriteType = WriteOnly` drops the read events altogether. The
  resulting zero looks exactly like "nothing pulled it". Read the trail's own configuration
  before treating an empty result as clean.
- AWS documents that for actions originating inside AWS *"only the DNS name is displayed"* —
  and the published pull example carries `sourceIPAddress: "ecr.amazonaws.com"`. Source-IP
  pivoting on pulls is unreliable by design.

## Response levers

**Error strings:** `PutImage` documents: `ImageAlreadyExistsException`, `ImageDigestDoesNotMatchException`,
**`ImageTagAlreadyExistsException`**, `InvalidParameterException`, `KmsException`,
`LayersNotFoundException`, `LimitExceededException`, `ReferencedImagesNotFoundException`,
`RepositoryNotFoundException`, `ServerException`. `PutImageTagMutability` documents only
`InvalidParameterException`, `RepositoryNotFoundException`, `ServerException`.

Denials come from ECR's common set: **`AccessDeniedException`** (HTTP 403) and
**`NotAuthorized`** (HTTP 401) are both documented; the bare `AccessDenied` form is what
IAM-evaluated denials produce across AWS and is widely observed but is **not** in ECR's
documented list. Match all three and confirm against a real denied event. The rest of the
common set — `ExpiredTokenException`, `ThrottlingException`, `ValidationError`,
`UnrecognizedClientException`, `ServiceUnavailable`, `InternalFailure` — is triage noise here
but belongs in any denial-counting query so probing is never counted as success.

Distinguish the two "already exists" errors, because they mean opposite things.
`ImageAlreadyExistsException` is *"the specified image has already been pushed, and there were
no changes to the manifest or image tag"* — a no-op re-push, benign.
`ImageTagAlreadyExistsException` is *"the specified image is tagged with a tag that already
exists. The repository is configured for tag immutability"* — a refused overwrite.

## On the manifest and CloudTrail's 100 KB cutoff

`PutImage`'s `imageManifest` parameter has a documented maximum length of 4,194,304
characters, which is above CloudTrail's 100 KB `requestParameters` omission threshold. This is
the rare technique where the size-based path is not automatically impossible. It is still not
worth a detection: a normal manifest is a couple of kilobytes, a manifest list large enough to
cross 100 KB would need thousands of entries, and `requestParameters.omitted` is **not a
documented CloudTrail field name** — do not invent it. Record the limit and move on. The same
reasoning does not apply to the policy techniques in this set: `policyText` is capped at
10,240 characters and `lifecyclePolicyText` at 30,720, both far below the cutoff.

**GuardDuty:** There is **no GuardDuty finding type for ECR repository configuration or image push
activity.** GuardDuty's container coverage is runtime monitoring on ECS, EKS and EC2 — it can
tell you a running container did something, not that the image it ran was substituted. Do not
build the response on a finding existing.

**MITRE:** The source maps **T1578 / TA0005** — *Modify Cloud Compute Infrastructure*. T1578 covers
compute infrastructure: instances, snapshots, images in the VM sense, backups. Relaxing a
container registry's tag-integrity setting is not that, so the mapping is wrong on the merits
even though the ID resolves.

Corrected primary: **T1525 — Implant Internal Image**, Persistence (TA0003). MITRE's own
description of T1525 is implanting a modified image into an environment's image repository so
that it is deployed by ordinary means, which is precisely what tag overwrite achieves.

Second mapping: **T1685 — Disable or Modify Tools**, Defense Impairment (TA0112). Tag
immutability is a deployed integrity control, and moving a repository off it — or carving
`latest` out of it — disables that control. The directory's
`stealth` segment tracks TA0005 (Stealth, formerly Defense Evasion), which is the tactic the
source labelled; the current canonical tactic for T1685 is Defense Impairment (TA0112).

**Severity:** **High**, against the source's **P4** — the largest priority disagreement in this set. The
setting change is silent, reversible-looking, and it is the enabling half of a compromise
whose other half leaves no attributable trace on the consumer side. A P4 on the only control
standing between a registry and an undetectable image substitution is a miscalibration, not a
judgement call.

**Files here:**

- `sigma_t1525.yml` — six documents: the weakening itself (`high`, all three
  overwrite-permitting values, both paths considered), the floating-tag carve-out (`high`),
  two base rules (`informational` — repository created overwritable, read from the nested
  response field; and image pushed), a `temporal_ordered` correlation firing `high` on
  weakening-then-push within thirty minutes, and the refused-overwrite error rule (`medium`).
- `kql_t1525.kql` — joins each weakening to the pushes that followed it on the same
  repository and projects `responseElements.image.imageId.imageDigest`, so the analyst sees
  the digests written rather than the tags claimed.

Siblings that share machinery: the repository-creation use case (not in this set) covers the
`CreateRepository` path as a use case in its own right and carries the same default-MUTABLE
trap; the excessive-image-push use case (not in this set) covers push volume;
`../../ecr.privilege-escalation.repository-policy-applied/` covers who is allowed to push at
all, which is the other half of this attack's precondition.

Full response procedure is in `../PLAYBOOK.md`.
