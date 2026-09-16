# Detection Note — T1578.005 (Modify Cloud Compute Infrastructure: Modify Cloud Compute Configurations)

**Signal:** a Lambda function's configuration changing — specifically the two fields that redirect
execution without touching a byte of code.

## The code hash is the wrong baseline for this technique

`Handler` repoints execution at a different method already inside the package. `Layers` attaches
code that loads with the function. Neither modifies the deployment package, so:

- `CodeSha256` is **unchanged**;
- code signing passes, because no code was signed differently;
- any package-hash drift check reports clean — including the one in `reference/PLAYBOOK.md`, which
  is built around exactly that hash.

AWS gives the right primitive in the same API response: **`ConfigSha256`**, the configuration's own
hash, returned by `GetFunctionConfiguration` alongside `CodeSha256`. Baselining against the code
hash alone leaves this whole technique invisible.

## A layer can come from another account

The `Layers` ARN pattern permits any 12-digit account. A layer attached from an account you do not
own is code running inside your function that you cannot read the contents of, and the only signal
is the account number embedded in the ARN. The query extracts it and compares against a populated
list, because nothing else will.

## No content check, twenty fields, one severity

The source rule matches every `UpdateFunctionConfiguration` and rates it P4. That call also changes
`Role`, `Environment`, `VpcConfig`, `KMSKeyArn`, `Runtime`, `Timeout` and `MemorySize`. A memory
bump and an execution-role swap arrive as the same alert, which is how the role swap gets closed.

Worth noting what the rule got **right**: it matches `/UpdateFunctionConfiguration.*/` with the
trailing wildcard, which is necessary because CloudTrail emits
`UpdateFunctionConfiguration20150331v2`. Two sibling rules in the same pack match `AddPermission`
without the suffix and therefore cannot fire — so the suffix was known to whoever wrote this rule and
dropped in the others.

## Response levers

**Read `ConfigSha256`, not `CodeSha256`.** It is the only hash that moves for this technique, and it
is returned by the same call.

**An execution-role change produces no IAM event.** No IAM object was modified — the function simply
points at a different role. Nothing in the IAM playbooks will show it, and comparing the two roles'
permissions is the actual triage.

**Environment variable values are unavailable from the event.** AWS: *"Omitted from AWS CloudTrail
logs."* The event tells you the key was present. Only a live `GetFunctionConfiguration` shows what
was set, and only to a principal permitted to read it.

**Publishing a version pins the configuration.** AWS: *"These settings can vary between versions of a
function and are locked when you publish a version. You can't modify the configuration of a published
version, only the unpublished version."* Invoking by published version rather than by `$LATEST`
removes this technique's effect entirely, which makes it the durable fix rather than a detection.

**Removing a function from a VPC is the direction worth reading.** AWS: *"When you connect a function
to a VPC, it can access resources and the internet only through that VPC."* Taking it out returns the
function to Lambda's own network, where none of your VPC egress controls apply.

**MITRE:** the source maps this to `T1584` — Compromise Infrastructure, a **Resource Development**
technique about compromising third-party infrastructure for use in operations. Modifying your own
function is not that. `T1578.005` is the primary mapping, with `T1525 — Implant Internal Image` on
the handler and layer case and `T1098.003` on the role change. All verified live 2026-08-30.

**GuardDuty:** Lambda Protection covers network activity from a running function —
`Backdoor:Lambda/C&CActivity.B`, `Trojan:Lambda/DropPoint`,
`UnauthorizedAccess:Lambda/TorClient`. Those fire on what the function does after it has been
tampered with, not on the configuration change. Complementary and strictly later.

**Files here:**
- `sigma_t1578_005.yml` — five documents: `lambda_execution_hijacked_by_config` (high, handler and
  layers), `lambda_execution_role_changed` (high), `lambda_network_or_key_changed` (medium),
  `lambda_function_config_changed` (informational base rule), and a `value_count` correlation for
  three or more functions reconfigured by one principal in an hour (high).
- `kql_t1578_005.kql` — extracts the owning account from a layer ARN to catch cross-account
  injection, and states inline that the code hash is the wrong baseline and that environment
  variable values are not in CloudTrail.

Full response procedure is in `../PLAYBOOK.md`.
