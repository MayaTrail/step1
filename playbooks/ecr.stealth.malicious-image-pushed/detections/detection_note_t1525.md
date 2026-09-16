# Detection Note — T1525 (Implant Internal Image)

**Signal:** an image pushed to ECR by a principal outside the deployment path — where one image is
the incident, not five.

## The push rule cannot fire, and fixing the casing is not enough

It matches `userIdentity.type:"iamuser"`. CloudTrail emits `IAMUser`, so on a case-sensitive field
the lowercase form matches nothing. Four other rules in the same ECR set spell it correctly.

Corrected, it would still miss the normal push path: `IAMUser` excludes **`AssumedRole`**, which is
every CI/CD pipeline and every SSO session. A compromised build role is the most likely route to this
call and it is precisely the identity type the filter removes.

The KQL projects `IdentityTypes` so both questions are answerable from one query: if a month of real
builds shows only `AssumedRole`, then even the casing-corrected rule would never fire.

## Volume is the wrong signal

The source ships this as a building block at five pushes in fifteen minutes. That is backwards in
both directions:

- **Too high for the attack.** One malicious image is the incident. Everything downstream that pulls
  the tag runs it.
- **Too low for the pipeline.** A normal CI run pushes several tags for a single build — `latest`, a
  semver, a commit SHA.

An allowlist of deployment roles replaces the threshold entirely, and it is the whole discriminator:
`PutImage` is what every deployment does.

## The public registry is a different outcome

The source rule matches `ecr-public.amazonaws.com` alongside the private registry, which is a genuine
strength worth naming. But it treats them identically, and they are not: a private push is contained
by deleting the image, while a push to the public registry has already distributed it outside the
account and outside the organisation. Deleting it does not un-distribute it. It ships as its own
rule for that reason.

## Response levers

**The event does not say what is in the image.** `PutImage` registers a manifest. The evidence is the
image digest and the scan findings — and if scanning was disabled first, see
`../../ecr.stealth.image-scanning-disabled/`.

**Check tag immutability before assuming a tag was overwritten.** An immutable repository rejects a
push to an existing tag, so on those repositories the technique must use a new tag, which is louder.
That setting is owned by `../../ecr.stealth.image-tag-overwrite-enabled/`.

**Read the repository name on a create-then-push.** An empty repository implants nothing, so the
creation is informational — but a new repository appearing with an image in it is how a lookalike or
typosquatted repository gets planted, and the name is the tell.

**Find what already pulled it.** The window between the push and containment is the exposure, and
every task or node that pulled the tag in that window is running the image. `BatchGetImage` is one
call per pull, so it is the right event to scope that question — see
`../../ecr.collection.excessive-images-pulled/`.

**MITRE:** the source maps the push to `T1578 — Modify Cloud Compute Infrastructure`, and ECR is a
registry rather than compute; it maps the repository creation to `T1525 — Implant Internal Image`,
which an empty repository is not. `T1525` is correct for the **push** and is used here for the pair.
Verified live 2026-08-30.

**GuardDuty:** no finding type covers ECR image pushes. `Execution:Container/MaliciousFile` and
`Execution:Kubernetes/MaliciousFile` fire from Malware Protection when a malicious file is detected
in a running container — that is after the image has been pulled and started, and it depends on
Runtime Monitoring being enabled. These rules are the earlier signal.

**Files here:**
- `sigma_t1525.yml` — five documents: `ecr_image_pushed_by_unexpected_principal` (high),
  `ecr_public_image_pushed` (high, because publication cannot be undone), `ecr_image_pushed` and
  `ecr_repository_created` (informational base rules), and a `temporal_ordered` correlation for a
  new repository created and populated by one principal (high).
- `kql_t1525.kql` — projects identity types as a coverage test of the original rule, and states
  inline that volume is deliberately not used as a signal.

Full response procedure is in `../PLAYBOOK.md`.
