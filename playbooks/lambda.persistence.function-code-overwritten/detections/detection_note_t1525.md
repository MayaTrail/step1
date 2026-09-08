# Detection Note — T1525 (Implant Internal Image)

**Signal:** a Lambda deployment package replaced by a principal that is not a recorded deployment
identity.

## The identity filter excludes the most likely attacker

The source rule requires `userIdentity.type:"IAMUser"`. SSO users, federated identities, EC2
instance roles, CI/CD roles and every cross-account path arrive as **`AssumedRole`** — including a
compromised deployment pipeline, which is the most plausible way this technique is actually
executed.

The KQL projects `IdentityTypes` for exactly this reason. If a month of real deployments shows only
`AssumedRole`, the original rule has never fired in that account and never will. That is a one-query
answer, and it is worth running before treating any of this as an incident.

Note the pack is inconsistent with itself: two of its four Lambda rules carry this filter and two do
not, for the same service and the same class of change.

## Rated P4 for certain code execution

Unlike a configuration change, this replaces the package. The new code **is** the handler, it runs on
every invocation under the function's execution role, and there is no second act to wait for. P4 is
below the threshold at which anyone looks.

## The code hash catches this, and misses its twin

`UpdateFunctionCode` moves `CodeSha256`, so a code-hash drift check works here.

It does **not** work for `../../lambda.defense-evasion.function-configuration-modified/`: changing
`Handler` or `Layers` redirects execution while leaving `CodeSha256` identical. A defender watching
only the code hash and a defender watching only the configuration are each blind to the other half,
and the two directories are deliberately cross-referenced for that reason.

## Response levers

**Read the refused attempts.** Code signing returns `CodeVerificationFailedException` on a signature
mismatch or expiry under an ENFORCE policy, and `InvalidCodeSignatureException` on an integrity
failure — which AWS notes blocks deployment *"even if the code signing policy is set to WARN"*.
Either is the control working, and a success-only rule discards it.

**Rollback depends on versions having been published.** A published version is immutable, so
repointing an alias at the last known-good version is a clean rollback. Where only `$LATEST` was ever
used, the previous package is gone and recovery means redeploying from source.

**Check the configuration alongside the code.** An actor who replaced the package may also have
changed the handler or added a layer, and only one of those moves the code hash.

**The full technique treatment is `reference/PLAYBOOK.md`.** This directory covers the source rule's
defects and the pairing; the drift baseline, the certain-versus-conditional execution reasoning and
the rollback procedure are there and are not restated here.

**MITRE:** the source maps this to `T1584` — Compromise Infrastructure, a **Resource Development**
technique about compromising third-party infrastructure for use in operations. Overwriting your own
function is not that. `T1525 — Implant Internal Image`, verified live 2026-08-30, matching the kit's
reference example for the same technique.

**GuardDuty:** Lambda Protection covers network activity from the running function —
`Backdoor:Lambda/C&CActivity.B`, `Trojan:Lambda/DropPoint`, `UnauthorizedAccess:Lambda/TorClient`.
Those fire on what the replaced code does, not on the replacement. Complementary and strictly later.

**Files here:**
- `sigma_t1525.yml` — four documents: `lambda_function_code_overwritten` (high, all identity types),
  `lambda_code_signing_rejected` (high, on the refused attempts a success filter drops),
  `lambda_function_code_changed` (informational base rule), and a `value_count` correlation for
  three or more functions in an hour (high).
- `kql_t1525.kql` — projects identity types as a coverage test of the original rule, and surfaces
  configuration changes alongside code changes so one query shows both halves of the pair.

Full response procedure is in `../PLAYBOOK.md`.
