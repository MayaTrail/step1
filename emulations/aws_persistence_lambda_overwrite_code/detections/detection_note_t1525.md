# Detection Note — T1525 / T1554 (Overwrite Lambda Function Code)

**Signal:** `lambda:UpdateFunctionCode` by a principal outside the deployment
pipeline — especially preceded by a `GetFunction` download of the original.

**Certain, not conditional.** Unlike the layer technique, the overwritten code
**is** the handler. It runs on **every** invocation, so compromise of the
function's execution role is certain rather than dependent on an import path.

**The original rule matched a read and a deploy** with a bare
`condition: selection`: `UpdateFunctionCode` fires on every legitimate deploy,
`GetFunction` on every console view and CI read, and neither the principal nor
the code hash was inspected.

## CodeSha256 is the ground truth

`responseElements.codeSha256` is the base64 SHA-256 of the deployed package. It
is the field that tells you the code actually changed, and to what.

**Field shape — returns `null` if you use the wrong one:**

```
get-function-configuration  ->  CodeSha256                  (FLAT)
get-function                ->  Configuration.CodeSha256    (NESTED)
```

Use the shape matching the call you actually make. A Config rule built from the
wrong prose gets `null` for every function and silently passes everything.

## Why a drift detector is not optional

The principal allowlist exempts the deploy pipeline — necessarily, or the rule
fires on every release. But that means **if the pipeline itself is
compromised, the CloudTrail rule stays silent.**

A `CodeSha256` baseline check does not: compare each function's live hash
against its known-good build hash on a schedule (Config custom rule or
scheduled job). That is the control that catches a compromised-pipeline
overwrite, and it is the reason this technique needs two detections rather than
one.

## Response levers

**Rollback is clean, if you published versions.** `UpdateFunctionCode` only
changes `$LATEST`. Published numbered versions are **immutable**, so a prior
published version is a trustworthy rollback target — repoint the alias to it
rather than trying to reconstruct code.

**Prevention:** Lambda **code signing** with
`UntrustedArtifactOnDeployment = Enforce` rejects unsigned deployments outright.

**Eradication scope:** emergency deny policies may have been attached to either
a role *or* a user depending on the suspect principal type — clean up both
`delete-role-policy` and `delete-user-policy` paths.

**Invoke is data-plane.** To establish whether the tampered code ran, see the
synchronous-invoke `requestParameters`-null trap in the
`lambda_backdoor_function` detection note.

**Error strings:** denials surface as `AccessDenied` / `AccessDeniedException`.
Not `Client.`-prefixed like EC2.

**MITRE:** the manifest maps T1525 (*Implant Internal Image*), which is
defensible, but **T1554** (*Compromise Host Software Binary*) is arguably
closer for overwriting a function's own code. Both tags are carried.

**Severity:** manifest MEDIUM; IR view **High** — certain code execution under
the execution role.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1525.yml` — three documents: non-deploy code overwrite (`high`), the
  download-then-overwrite sequence (`high`), and the `GetFunction` base rule
  (`low`).
- `kql_t1525.kql` — both signals plus the drift-detector, rollback and code
  signing guidance inline.

Full response procedure is in `../PLAYBOOK.md`.
