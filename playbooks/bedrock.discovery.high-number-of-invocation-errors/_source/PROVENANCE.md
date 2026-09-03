# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | **Building block with no shipped logic** — no query, no threshold, no group-by |
| Scope captured | One entry: High Number of Invocation Errors |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

## A new use case, not a corrected rule

The source entry is a **building block** with no query, no threshold and no grouping — a CloudWatch
metric alarm for availability. There is no logic to audit, so the `Issue | Impact | Correction`
table in `../PLAYBOOK.md` §2 records what the source provides and what a security detection needs,
rather than inventing defects in an empty rule.

**The security reading of "invocation errors" is enumeration**, and the error **code** is the
information the attacker is buying:

- `AccessDeniedException` — the model exists and is enabled in this Region, and this principal
  cannot use it. A *positive* result for enumeration: it maps the boundary of the permission.
- `ValidationException` — not enabled in this Region, or the request shape is wrong for that model.
  Separates "not available" from "not allowed", which is exactly the distinction being sought.
- `ThrottlingException` — the call was **permitted** and rate-limited. One of these among a hundred
  refusals is more significant than all of them together.

An availability alarm counts "errors" and merges all three, losing every distinction that matters.

**This use case is CloudTrail-only by construction**, and that is a strength rather than a
limitation. A call that failed authorisation produced no invocation, so the model invocation log —
which is off by default — has nothing to contribute. The detection therefore works in the common
case where invocation logging was never enabled, which is the opposite of the sibling playbook at
`../../bedrock.impact.high-invocation-count/`.

**Grouping is by `userIdentity.accessKeyId`** rather than by ARN, because one leaked credential is
used across several sessions and the key is what identifies it.

**MITRE:** the source maps this to nothing. `T1526 — Cloud Service Discovery` for the enumeration,
with `T1078.004 — Valid Accounts: Cloud Accounts` on the volume rule. Both verified live 2026-08-30.

**Merge test:** the four documents are one use case — a credential mapping what it can reach —
observed through breadth, volume and the control-plane grant that follows. None has a source rule of
its own.

**Tier:** 2 — lean: the response is short and the analytic step is a single read.

Service ground truth for every `bedrock.*` playbook is in `../../_ground-truth/bedrock.md`, audited on
2026-08-30. The control plane is §5; logging being off by default is §1.
