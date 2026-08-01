# Detection Note — T1059 (Malicious Script Execution via SageMaker Lifecycle Config)

**Signal:** `sagemaker:UpdateNotebookInstanceLifecycleConfig` (or `Create…`)
carrying a base64-encoded OnStart script, written by a principal outside the
provisioning pipeline.

**The payload is in the event.** The OnStart/OnCreate `content` field is
base64-encoded in `requestParameters` — decode it and match on the script body.
This is the strongest signal available for the technique and it costs one
decode step. Rules that only match the event name throw it away.

**Substring, not whole-term, matching.** Whole-term matchers (`has_any` in KQL)
do not reliably match `/dev/tcp` or `base64 -d` because of the slash and space
delimiters — and those are exactly the payloads of interest. Use `contains`.

**Drop the `Describe`.** The original rule ORed
`DescribeNotebookInstanceLifecycleConfig` into the selection, so a routine read
fired the same alert as a malicious write.

**Include `Create*`.** An attacker can create a *new* malicious config and
attach it to a notebook, which an Update-only rule never sees.

**Why this is persistence-flavoured execution:** the script runs automatically
every time the notebook instance starts, under the notebook's **execution
role**. That role is the blast radius — treat its credentials as compromised
once a malicious script has run.

**CLI detail:** `--on-start "Content=$B64"` takes a plain pre-encoded string.
It is not a blob parameter, so the CLI does not base64 it for you — the value
you pass is what lands in CloudTrail.

**Error strings:** SageMaker denials surface as `AccessDenied` /
`AccessDeniedException`, not `Client.`-prefixed like EC2. Match both if you add
a permission-probing rule.

**Severity:** manifest MEDIUM; IR view **High** — recurring code execution
under a role. T1059 is a reasonable mapping; no caveat needed.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1059.yml` — two documents: the non-provisioning write rule (`high`)
  and the content-matched rule (`critical`). The latter needs a pipeline that
  decodes the base64 into a `DecodedOnStart` field.
- `kql_t1059.kql` — decodes inline with `base64_decode_tostring`, so it works
  without pipeline support. Note it decodes `onStart[0]` only; use `mv-expand`
  for exhaustive coverage of multi-entry configs.

Full response procedure is in `../PLAYBOOK.md`.
