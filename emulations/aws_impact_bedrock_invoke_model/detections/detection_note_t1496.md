# Detection Note: T1496 (Invoke Bedrock Model for Resource Exhaustion)

**Signal:** `bedrock:InvokeModel` at high volume from a single principal, and a
matching spike in Bedrock spend.

**`InvokeModel` is a CloudTrail management event.** It appears in the default
trail with no data-event configuration required. This is worth stating plainly
because the opposite assumption, that it is data-plane like `lambda:Invoke` or
`ses:SendEmail`, is easy to make and would send a responder hunting in the
wrong place entirely.

**The shipped rule is fixable, not broken.** Unlike most rules in this set it
does fire. Its defects are precision:

| Defect | Effect |
|---|---|
| No threshold | Fires on the constant legitimate traffic of any ML workload; gets muted |
| No `eventSource` scoping | Imprecise; risks event-name collisions |
| `InvokeModel` only | Streaming and Converse APIs achieve the same and evade it |

**Volume is the technique.** One invocation is a workload; thousands in ten
minutes from one principal is cost abuse. Threshold per principal per window
and tune the number to your baseline, the emulation loops rapidly, real
inference services do too, and the gap between them is local.

## Three complementary controls

CloudTrail alone is not sufficient here, because of what it does **not**
record:

1. **CloudTrail volume rule** (in this directory), who called, how often. The
   primary, zero-config detection.
2. **CloudWatch `AWS/Bedrock` alarms**, `InputTokenCount` and
   `InvocationThrottles` per model. CloudTrail shows that a call happened, not
   how large it was, and Bedrock bills **per token**: 100 huge-context calls
   can cost more than 10,000 small ones. Throttles additionally reveal quota
   exhaustion, which is a denial-of-service against your own workloads.
3. **Cost Anomaly Detection** on Bedrock spend, the backstop that catches
   whatever the first two miss.

**Prompt and completion content** appear in neither CloudTrail nor CloudWatch.
They exist only in **model invocation logging**, and only if it was enabled.
Which is why the third Sigma rule watches for that logging being deleted or
weakened, an actor who disables it removes the only record of what was
actually asked of the model.

**Error strings:** Bedrock denials surface as `AccessDeniedException`,
throttling as `ThrottlingException`. Not `Client.`-prefixed like EC2.

**MITRE:** T1496 (*Resource Hijacking*) is the correct mapping, no caveat
needed. The logging-disable rule carries T1685.002 separately.

**Severity:** manifest MEDIUM; IR view **High**, a fast-accruing, directly
monetary impact with a denial-of-service side effect when quotas are exhausted.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1496.yml`, three documents: the invocation base rule (`low`), the
  volume correlation (`high`), and the logging-disabled rule (`high`).
- `kql_t1496.kql`, volume detection with throttle/denial verdicts, and notes
  on the CloudWatch metrics it cannot replace.

Full response procedure is in `../PLAYBOOK.md`.
