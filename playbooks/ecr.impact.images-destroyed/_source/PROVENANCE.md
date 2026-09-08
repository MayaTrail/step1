# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rules over query strings |
| Scope captured | Three rules: Images Within a Repository Deleted, Forced Repository Deleted, Life-Cycle Policy Added |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project. Each rule
excluded a single named human principal by ARN; that value is redacted in the extract and the defect
it represents is described in `../../_ground-truth/ecr.md` §3.

**Merge test — applied, not assumed. Three source rules, one use case, because destruction has three
shapes.** `BatchDeleteImage` removes images now; `DeleteRepository` with force removes the repository
and its images now; `PutLifecyclePolicy` expires images on a schedule. They share one response —
establish what was destroyed, whether it is recoverable, and what depended on it — so they merge. The
source pack files them under three different tactics and maps them to three different techniques.

**Nothing deleted from ECR is recoverable.** There is no versioning, no recycle bin and no undelete,
unlike S3 where a delete marker can be removed. Once a digest is gone the layers are gone and
recovery means rebuilding from source. That inverts the usual response priority: establishing *what*
was destroyed matters more than restoring it, because restoration is not available.

**The `force: true` filter is a narrow slice of the technique.** `DeleteRepository` succeeds
*without* force when the repository is empty, so deleting every image first and then the repository
reaches the same end state and never sets the flag. The shipped rule matches both paths and reports
the flag rather than requiring it.

**The lifecycle rule has no content check and is rated as privilege escalation.** A lifecycle policy
is ordinary cost management; an aggressive one deletes images days later with no further event
naming them, which makes it the quietest of the three. The source rule fires on every policy equally
and maps to `T1484 — Domain or Tenant Policy Modification`, which is about directory and tenant
policy rather than a registry retention rule. The correct triage is
`StartLifecyclePolicyPreview`, which reports exactly which images a policy *would* remove without
removing them — and the shipped playbook runs it before rating anything.

**The three rules group by different fields** — two by `userIdentity.principalId`, one by
`repositoryName` plus `userIdentity.arn`. Sibling rules over the same resource at two granularities
cannot be correlated with each other, which is why the pack has no destruction-at-breadth signal at
all. The shipped correlation supplies one.

**One thing the source got right:** the `BatchDeleteImage` rule's identity filter includes
`AssumedRole` where the push and pull rules in the same pack do not. The pack is inconsistent with
itself about who counts as a principal, and this rule is on the correct side of that inconsistency.

**MITRE:** `T1485 — Data Destruction` is the source's own mapping for `BatchDeleteImage` and is
correct; it is used for all three here. `T1578` on repository deletion (ECR is a registry, not
compute) and `T1484` on the lifecycle policy are both wrong. Verified live 2026-08-30.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `ecr.*` playbook is in `../../_ground-truth/ecr.md`, audited 2026-08-30.
§5 covers the three destruction shapes.
