# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rules over query strings |
| Scope captured | Two rules: Excessive ECR Image Pushed (building block), Repository Created |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project. One rule
excluded a single named human principal by ARN; that value is redacted in the extract and the defect
it represents is described below.

**Merge test — applied, not assumed. Two source rules, one use case.** `PutImage` and
`CreateRepository` are joined by a sequence rather than by similarity: an empty repository implants
nothing, so `CreateRepository` is not a finding on its own, and its value is entirely as the first
half of a new-repository-with-an-image-in-it pair. Shipping it separately would leave a directory
whose only rule must never be routed. `PutImage` to the **public** registry is kept as its own
document rather than merged into the private rule, because the outcome differs — publication cannot
be undone by deleting the image.

**The push rule cannot fire.** It matches `userIdentity.type:"iamuser"`. CloudTrail emits `IAMUser`,
and on a case-sensitive field the lowercase form matches nothing. Four other rules in the same ECR
set spell it correctly, so the pack writes one field two ways.

**Corrected, the filter would still miss the normal push path.** `IAMUser` excludes `AssumedRole` —
every CI/CD pipeline and every SSO session. The pushes a detection most wants to see, from a
compromised build role, are exactly the ones the filter removes. The shipped KQL projects
`IdentityTypes` so a reviewer can settle both questions from one query against their own account.

**Volume is the wrong signal and is not used here.** The source ships the push rule as a building
block at five pushes in fifteen minutes. A single malicious image is the incident, and a normal CI
run pushes several tags for one build — so the threshold is simultaneously too high to catch the
attack and too low to avoid the pipeline. An allowlist of deployment roles replaces it.

**Every rule in the ECR set excludes the same named human by ARN.** A personal allowlist compiled
into the detection logic for an entire service: if that identity is compromised or impersonated, all
seven rules go blind at once. Replaced with a populated provisioner list a responder can read and
change.

**The repository rule carries `NOT "TLSv1.3"`** — an unfielded term negation, not bound to any
field, which discards any event whose serialised record contains that string. That is the TLS version
of the call itself, and modern SDKs negotiate TLS 1.3 by default, so the clause excludes much of the
traffic the rule exists to inspect.

**What the source got right:** the push rule matches `ecr-public.amazonaws.com` alongside the private
registry. Publication to the public registry is a genuinely different outcome and the source pack was
alone among its peers in covering it at all.

**MITRE:** the source maps the push to `T1578 — Modify Cloud Compute Infrastructure` (ECR is a
registry, not compute) and the repository creation to `T1525 — Implant Internal Image` (an empty
repository implants nothing). `T1525` is correct for the **push** and is used here for both, with the
repository rule shipped at informational so the mapping describes the pair rather than the empty
resource. Verified live 2026-08-30.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `ecr.*` playbook is in `../../_ground-truth/ecr.md`, audited 2026-08-30.
