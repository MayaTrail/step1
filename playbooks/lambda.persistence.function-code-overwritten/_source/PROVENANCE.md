# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string with a regex on the event name |
| Scope captured | One alerting rule: Function Modified by IAM User |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook, and it had no detection there.** This rule was one of four
in `aws.persistence.lambda-resource-policy-backdoor`, whose five Sigma documents all address the
resource policy. `UpdateFunctionCode` was carried in `_source/` and covered by nothing.

**It matches `userIdentity.type:"IAMUser"` only, which excludes almost every modern principal.** SSO
users, federated identities, EC2 instance roles, CI/CD roles and every cross-account path arrive as
`AssumedRole` — including a compromised deployment pipeline, which is the most likely way this
technique is actually executed. Two of the four rules in the pack carry this filter and two do not,
so the pack is inconsistent with itself about who counts as a principal. The shipped KQL projects
`IdentityTypes` precisely so a reviewer can confirm, from one query against their own account,
whether the original rule has ever fired there.

**Rated P4, for certain code execution under the function's role.** Unlike a configuration change,
this replaces the deployment package — the new code *is* the handler, it runs on every invocation,
and no second act is required.

**The event-name wildcard is correct, and that is worth recording.** CloudTrail emits
`UpdateFunctionCode20150331v2`, and `/UpdateFunctionCode.*/` handles it. Two sibling rules in the
same pack match `AddPermission` without the suffix and therefore cannot fire — the suffix was known
to whoever wrote this rule and dropped in the others.

**And it maps to `T1584`** — Compromise Infrastructure, a **Resource Development** technique about
adversaries compromising third-party infrastructure to use in their own operations. Overwriting your
own function's code is not that. All four rules in the original pack carry it.

**Deliberate scope limit.** The full treatment of this technique — the `CodeSha256` drift baseline,
the rollback-to-published-version procedure, the reasoning about certain versus conditional execution
— is the kit's worked example in `reference/PLAYBOOK.md`, and this directory does not restate it.
What is here instead is the source-rule analysis and the pairing with
`../../lambda.defense-evasion.function-configuration-modified/`: a handler or layer change redirects
execution while leaving `CodeSha256` **unchanged**, so a defender watching only the code hash and a
defender watching only the configuration are each blind to the other half.

**MITRE:** `T1525 — Implant Internal Image`, verified live 2026-08-30, matching the mapping the kit's
reference example uses for the same technique.

**Merge test:** not applicable — one source rule, one use case. Kept apart from
`../../lambda.persistence.resource-policy-backdoor/`, which governs who may invoke rather than what
runs, and from the configuration atom, which redirects execution without changing the package.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.