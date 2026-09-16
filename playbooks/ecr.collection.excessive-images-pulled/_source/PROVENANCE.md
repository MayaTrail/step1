# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One rule: Excessive ECR Images Pulled (building block) |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project. The rule
excluded a single named human principal by ARN; that value is redacted in the extract and the defect
it represents is described below.

**The rule cannot fire, and correcting it barely helps.** It matches `userIdentity.type:"iamuser"`;
CloudTrail emits `IAMUser`, so on a case-sensitive field it matches nothing. Corrected, it would
still exclude `AssumedRole` — and image pulls are almost entirely `AssumedRole`: every ECS task
role, every EKS node role, every CI runner. The identity type is not a useful discriminator for this
operation in either spelling, which is why the shipped rules drop it and use a puller allowlist and
a breadth correlation instead.

**`BatchGetImage` counts pulls but does not mean content moved.** AWS: *"When an image is pulled,
the BatchGetImage API is called once to retrieve the image manifest."* That makes it a fair proxy
for pull **count** — better than it first appears. But the response carries `imageManifest` only;
the layer bytes come from `GetDownloadUrlForLayer`, and a client that already has the layers cached
pulls the manifest and downloads nothing. Where the question is exfiltration, the layer call is the
one that corresponds to data movement, and the source rule does not watch it. It ships here as an
informational base rule so a responder can compare the two counts.

**Volume is the wrong axis and breadth is the right one.** Ten pulls in fifteen minutes is a node
starting up or a deployment rolling out — all from one or two repositories. Ten pulls across ten
different repositories is someone walking the registry. The source rule counts pulls and cannot
separate them; the shipped correlation counts **distinct repositories**.

**And it excludes the same named human as every other rule in the ECR set**, by ARN, inline. See
`../../_ground-truth/ecr.md` §3.

**MITRE:** `T1530 — Data from Cloud Storage`, which is the source's own mapping and is correct — a
container image is stored data and pulling it is how the contents leave. Verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case. Kept apart from
`../../ecr.stealth.malicious-image-pushed/` because pulling and pushing are opposite directions with
opposite responses: a push is contained by deleting the image, a pull has already happened and is
contained by rotating whatever the image contained.

**Tier:** 1, on criterion 2 of `07-TIERS.md` — *the response has ordering that can go wrong*.

Service ground truth for every `ecr.*` playbook is in `../../_ground-truth/ecr.md`, audited 2026-08-30.
§1 covers what `BatchGetImage` does and does not tell you.
