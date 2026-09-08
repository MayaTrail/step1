# Detection Note — T1485 (Data Destruction)

**Signal:** container images removed — immediately, or on a schedule nobody looks at.

## Nothing deleted from ECR is recoverable

There is no versioning, no recycle bin, no undelete. Unlike S3, where a delete marker can be
removed, an ECR digest that is gone is gone and the layers with it.

That inverts the usual response priority. Every other destruction playbook in this set spends its
containment on restoring; here restoration is not available, so establishing **what** was destroyed
— and what depended on it — is the whole job.

## Three shapes, and the quietest is rated as privilege escalation

| Call | Effect | Source rating |
|---|---|---|
| `BatchDeleteImage` | Images removed now | P4, `T1485` — correct technique |
| `DeleteRepository` + `force` | Repository and all images removed now | P4, `T1578` — ECR is not compute |
| `PutLifecyclePolicy` | Images expire days later, on a schedule | P4, `T1484` — a retention rule is not tenant policy |

The lifecycle policy is the one that matters most and is filed furthest from the truth. Nothing is
deleted at the time, so there is no destruction event to correlate with; the images go days later
with **no further event naming them**.

## `force: true` is a narrow slice of the technique

`DeleteRepository` succeeds *without* force when the repository is empty. Delete the images first,
then the repository, and the end state is identical while the flag the source rule requires is never
set. Both paths are matched here, and the flag is reported rather than required.

## Response levers

**`StartLifecyclePolicyPreview` is the authority on a lifecycle finding.** It reports exactly which
images a policy would remove, without removing them:

```
aws ecr start-lifecycle-policy-preview --repository-name <repo> --lifecycle-policy-text <json>
aws ecr get-lifecycle-policy-preview   --repository-name <repo>
```

Run it before rating. The heuristics in the shipped query — aggressive counts, `tagStatus: tagged` —
will be wrong in both directions, and the preview will not.

**Find what depended on the images before anything else.** A deleted digest that nothing runs is a
housekeeping event; one that a production task definition or a Kubernetes deployment references is an
outage waiting for the next scale-out. That question is answered from ECS task definitions and
cluster manifests, not from ECR.

**A running container survives its image being deleted.** It keeps running from local layers until
it is restarted or rescheduled, so the impact is deferred and will present as a failure to launch
rather than as a crash. That delay is why this is often discovered days later.

**Rebuild is the only recovery.** If the source and the build pipeline are intact, the digest can be
reproduced — though not byte-identically unless the build is reproducible. If they are not, the image
is unrecoverable.

**MITRE:** `T1485 — Data Destruction`, which is the source's own mapping for `BatchDeleteImage` and
is correct for all three shapes. `T1578` on repository deletion and `T1484` on the lifecycle policy
are both wrong. Verified live 2026-08-30.

**GuardDuty:** no finding type covers ECR deletion. `Impact:S3/AnomalousBehavior.Delete` is the
nearest analogue for a different service and has no ECR equivalent, so these rules are the only
coverage.

**Files here:**
- `sigma_t1485.yml` — five documents: `ecr_repository_deleted` (critical, matching both the forced
  and unforced paths), `ecr_images_deleted` (high), `ecr_lifecycle_policy_applied` (medium, because
  the preview resolves it), `ecr_image_destruction` (informational base rule), and a `value_count`
  correlation for destruction across three or more repositories in an hour (critical) — a signal the
  source pack cannot produce, because its three rules group by different fields.
- `kql_t1485.kql` — separates forced from unforced repository deletion, applies heuristics to the
  lifecycle policy text while naming the preview as the authority, and states inline that nothing is
  recoverable.

Full response procedure is in `../PLAYBOOK.md`.
