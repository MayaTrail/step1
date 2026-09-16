# Detection Note — T1685.002 (Disable or Modify Tools: Disable or Modify Cloud Log)

**Signal:** the model invocation log goes quiet while CloudTrail continues to show invocations.

**This is the only `*.stealth.no-logs-*` playbook in the corpus with a second witness, and it
changes the argument entirely.** Bedrock invocations are recorded in two independent places:

- **The model invocation log** — who, which model, how many tokens, **and the prompt and the
  response**. Off by default.
- **CloudTrail `bedrock-runtime` data events** — who and which model, never the content.

`DeleteModelInvocationLoggingConfiguration` stops the first and leaves the second untouched. So:

| Invocation log | CloudTrail | Meaning |
|---|---|---|
| quiet | quiet | The workload stopped. Availability, not security |
| quiet | **busy** | **Logging was removed while invocations continue** |

Everywhere else in this project an absence rule has to be demoted to a corroborator because silence
is ambiguous. Here it is not: the second source resolves it, and the divergence query in the KQL is
the primary detection rather than a fallback.

**The source entry has no logic to correct.** It is a building block — a CloudWatch metric alarm on
invocation volume — so this is a new security use case and the §2 table says so rather than
inventing defects in an empty rule.

## Three paths, and the quiet one produces no divergence at all

**Delete the configuration.** Loud, immediate, and it produces the divergence above. One
configuration per account per Region, so a single call blinds the whole Region.

**Reconfigure with a modality disabled.** Logging is enabled per modality — text, image, embedding,
video — and AWS records bodies only for the modalities selected. Turning one off leaves the
configuration present, the console showing logging enabled, and **both sources still producing
records**. Only the *content* for that modality stops. This produces no divergence whatsoever, and
only the control-plane event reveals it — which is why `bedrock_invocation_logging_narrowed` ships
at the same level as the deletion.

**Remove the destination.** Deleting the S3 bucket or the log group, or replacing the bucket policy
so the `bedrock.amazonaws.com` principal can no longer write, stops delivery while
`GetModelInvocationLoggingConfiguration` still returns a healthy configuration. **There is no
Bedrock-side error event when delivery starts failing** — nothing is called — so a configuration
check alone will not find it, and only the divergence query or a destination read will.

## Off by default, which complicates "removed"

AWS: *"Model invocation logging is disabled by default."* So an account that never enabled it looks
exactly like one where it was removed, judged by the log streams alone. The control-plane events
separate them, and so does the state read in Query 2 — which matters for an account where the
deletion predates the CloudTrail retention window.

## Response levers

**Restoring does not recover anything.** Logging cannot be applied retroactively, so the prompts and
responses for the gap do not exist and never will. If the concern is what was generated using the
organisation's models — content produced in its name, or data placed into a prompt — that question
is permanently unanswerable for the affected period. The CloudTrail record still says *who* and
*which model*, which bounds the exposure without describing it.

**Check the destination, not just the configuration.** The newest object in the S3 prefix or the
newest stream in the log group is the only evidence that delivery works. And note the 100 KB rule:
bodies over that, plus all binary data, are stored as separate S3 objects under the data prefix — so
a healthy invocation-log entry count says nothing about whether the large content landed, and a
lifecycle rule on that prefix destroys exactly the large prompts most worth keeping.

**Confirm the trail covers Bedrock.** The divergence check needs CloudTrail's `bedrock-runtime` data
events. Without them the second witness does not exist, the query reports "logged without a trail
record", and this playbook's central advantage is gone — which is a CloudTrail finding rather than
a Bedrock one.

**MITRE:** the source maps this to nothing. `T1685.002 — Disable or Modify Cloud Log`, verified live
2026-08-30. The sub-technique choice is deliberate: the invocation log is a **log**, so `.002`,
where `../../guardduty.stealth.no-logs-from-amazon-guardduty/` uses `.001` because GuardDuty is a
**tool**.

**Severity:** high for deletion and for a disabled modality, medium for destination tampering. The
modality case is rated equal to deletion because it is quieter, more selective, and invisible to the
divergence check.

**GuardDuty:** no coverage. There is no finding type for Bedrock configuration.

**Files here:**
- `sigma_t1685_002.yml` — three CloudTrail documents: `bedrock_invocation_logging_deleted` (high),
  `bedrock_invocation_logging_narrowed` (high, the path with no divergence), and
  `bedrock_log_destination_tampered` (medium).
- `kql_t1685_002.kql` — the two-source divergence query as the primary detection, with the
  control-plane view in a commented second section.

Full response procedure is in `../PLAYBOOK.md`.
