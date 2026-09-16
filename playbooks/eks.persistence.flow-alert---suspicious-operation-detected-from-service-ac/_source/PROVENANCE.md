# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | FLOW composition over Kubernetes audit building blocks |
| Scope captured | One alerting rule: Flow Alert - Suspicious Operation Detected From Service Account |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public MITRE, AWS and Kubernetes documentation only.

## A limit on what could be audited, stated rather than papered over

The source rule is a FLOW whose stages are `(6)` then `(10 AND 24)` over three hours,
grouped by `user.username`. **It references those stages by bare internal ID, and the
referenced building blocks are not in the extract** — they are separate entries in the
source pack. So what the flow actually matches could not be reconstructed from the artifact,
and the shipped detections do **not** claim to reproduce it.

What they do instead is build on the observable the rule's title names — a ServiceAccount
performing control-plane operations that establish persistence — using facts from the EKS
audit policy that *can* be verified. Where the `Issue | Impact | Correction` table in
`../PLAYBOOK.md` §2 comments on the flow, it comments on its **structure** (opaque stage
references, a three-hour window, `group_by user.username`), not on stage contents it cannot
see. That distinction is deliberate.

**MITRE:** mapped to **T1098.006 — Account Manipulation: Additional Container Cluster
Roles**, verified live. The source rule carries bare `T1098`, which is the parent; `.006`
names container-cluster role manipulation exactly. A mapping-precision refinement, not a
correction. `T1552.007` is carried as a secondary tag for the secret-read rules.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 1 of `07-TIERS.md` — *account takeover is reachable in one further hop*.

Service ground truth for every `eks.*` playbook is in `../../_ground-truth/eks.md`, audited once
on 2026-08-29. The audit-policy levels are §3; the two identity systems and the containment
asymmetry are §5.
