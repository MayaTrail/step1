# Detection Note — T1530 (Data from Cloud Storage)

**Signal:** images pulled across many repositories — breadth, not volume.

## The rule cannot fire, and fixing the casing barely helps

It matches `userIdentity.type:"iamuser"`. CloudTrail emits `IAMUser`, so it matches nothing.

Corrected, it would still exclude `AssumedRole` — and image pulls are **almost entirely**
`AssumedRole`: ECS task roles, EKS node roles, CI runners. This is the unusual case where the
identity-type filter is useless in both spellings, because the operation is performed by roles by
design. The shipped rules drop it entirely.

## `BatchGetImage` counts pulls; it does not mean content moved

> *"When an image is pulled, the BatchGetImage API is called once to retrieve the image manifest."*

So it is a fair proxy for pull **count** — better than it first appears, and worth saying because the
obvious criticism ("it's only the manifest") overstates the problem. What it genuinely cannot tell
you is whether image **content** transferred: the response carries `imageManifest` only, the layers
come from `GetDownloadUrlForLayer`, and a client with the layers already cached pulls the manifest
and downloads nothing.

The KQL projects both counts. High pulls with low layer fetches is a fleet restarting on cached
images. Where the question is exfiltration, the layer count is the one that matters.

## Volume is the wrong axis

Ten pulls in fifteen minutes is a node starting up or a deployment rolling out — all from one or two
repositories. Ten pulls across ten **different** repositories by one principal is someone walking the
registry.

The source rule counts pulls and cannot separate those. The shipped correlation counts distinct
repositories, which is why it needs no allowlist to be useful: a rollout does not touch five
repositories and a walk does.

## Response levers

**Enumeration before the pull is the strongest shape.** `DescribeRepositories` or `ListImages`
followed by pulls across many repositories has no deployment reading — a workload pulls the image it
was configured with and does not look around first.

**Containment is rotation, not deletion.** Unlike a push, a pull has already happened. What matters
is what the image contained — embedded credentials, configuration, proprietary code — and those need
rotating or treating as disclosed. Deleting the image afterwards changes nothing.

**Check the public registry column.** A pull from `ecr-public` is ordinary; a *push* there is not, and
that is `../../ecr.stealth.malicious-image-pushed/`.

**MITRE:** `T1530 — Data from Cloud Storage`, which is the source's own mapping and is correct.
Verified live 2026-08-30.

**GuardDuty:** no finding type covers ECR pulls. `Exfiltration:S3/AnomalousBehavior` is the nearest
analogue for a different service and has no ECR equivalent, so these rules are the only coverage.

**Files here:**
- `sigma_t1530.yml` — four documents: a `value_count` correlation on **distinct repositories**
  (high, the routable output), `ecr_pull_by_unexpected_principal` (medium), and `ecr_image_pulled`
  and `ecr_layer_download_issued` as informational base rules — the second being the call that
  corresponds to content actually transferring.
- `kql_t1530.kql` — reports pulls and layer fetches separately, computes a repositories-per-pull
  ratio to separate a rollout from a walk, and flags enumeration preceding the pulls.

Full response procedure is in `../PLAYBOOK.md`.
