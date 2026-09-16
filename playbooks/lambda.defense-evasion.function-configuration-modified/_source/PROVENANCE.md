# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string with a regex on the event name |
| Scope captured | One alerting rule: Settings of a Lambda Function Modified |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook, and it had no detection there at all.** This rule was one
of four in `aws.persistence.lambda-resource-policy-backdoor`, whose five shipped Sigma documents all
address the resource policy. `UpdateFunctionConfiguration` was carried in `_source/` and covered by
nothing — a quieter failure than aggregation, because the scope looked covered and was not.

**The rule has no content check on a call that changes twenty different things, and rates it P4.**
`UpdateFunctionConfiguration` accepts `Handler`, `Layers`, `Role`, `Environment`, `VpcConfig`,
`KMSKeyArn`, `Runtime`, `Timeout`, `MemorySize` and more. A memory bump and an execution-role swap
arrive as the same alert.

**Two of those fields hijack execution without touching code, which is why this matters.**

- `Handler` — *"The name of the method within your code that Lambda calls to run your function."*
  Repointing it runs a **different function already inside the package**.
- `Layers` — *"A list of function layers to add to the function's execution environment."* A layer is
  code, it loads with the function, and its ARN pattern permits **any 12-digit account** — so the
  injected code can be something the function owner cannot read.

Neither modifies the deployment package. `CodeSha256` is unchanged, so code signing, package-hash
baselines and the code-drift detection in `reference/PLAYBOOK.md` all still pass. AWS provides the
right primitive in the same response: **`ConfigSha256`**, the configuration's own hash, which is what
the playbook baselines against.

**Environment variable values are not recoverable from CloudTrail.** AWS on the response element:
*"The function's environment variables. Omitted from AWS CloudTrail logs."* A rule can see that the
key was present and cannot see what was set — only a live `GetFunctionConfiguration` shows the
current values.

**The event name carries a version suffix.** CloudTrail emits `UpdateFunctionConfiguration20150331v2`.
The source rule's `/UpdateFunctionConfiguration.*/` handles this correctly, which is worth recording
because two sibling rules in the same pack match `AddPermission` without the suffix and therefore
cannot fire — the suffix was known to whoever wrote this rule and dropped in the others.

**And it maps to `T1584`.** That is Compromise Infrastructure, a **Resource Development** technique
about adversaries compromising third-party infrastructure to use in their own operations. Modifying
your own Lambda function is not that. All four rules in the original pack carry it.

**MITRE:** `T1578.005 — Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations` is
the primary mapping — the technique is literally modifying a cloud compute configuration.
`T1525 — Implant Internal Image` is tagged on the handler and layer case, where the effect is
implanted code; `T1098.003` on the execution-role change. All verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case. It is kept apart from
`../../lambda.persistence.resource-policy-backdoor/` because that governs **who may invoke** the
function while this governs **what the function is and does**, and apart from
`../../lambda.persistence.function-code-overwritten/` because that changes the package and this
deliberately does not.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth shared by every `lambda.*` playbook lives in the sibling directories' provenance
until a `_ground-truth/lambda.md` exists; the API facts above are cited inline.
