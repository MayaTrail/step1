# Detection Note: T1098 (Backdoor SQS Queue via Open Resource Policy)

**Signal:** `sqs:SetQueueAttributes` in CloudTrail where the injected `Policy`
attribute contains `Principal: "*"` (or `{"AWS": "*"}`) on a production queue.

**Why this is serious:** the backdoor lives in the **queue's resource policy**,
not in any credential. It grants any AWS principal — including anonymous callers
in some configurations — `SendMessage` / `ReceiveMessage` / `DeleteMessage`.
An attacker can drain messages (data exfiltration) or inject poisoned messages
into a downstream processing pipeline. Rotating the compromised role's keys does
not remove the policy.

## Where the policy shows up in the event

CloudTrail records the full policy JSON inside
`requestParameters` — the SDK sends it as the `Policy` attribute of
`SetQueueAttributes`. Unlike IAM `policyDocument`, the SQS `Policy` value is
**not URL-encoded**, so substring matches on `"Principal":"*"` work directly.
Account for both spacing variants (`"Principal":"*"` and `"Principal": "*"`) and
the object form (`"Principal":{"AWS":"*"}`).

## The three rules shipped here

`sigma_t1098.yml` holds three documents:

- **SQS Queue Resource Policy Set to Wildcard Principal** (`high`) — the
  standing detection. Fires on the step-3 injection.
- **SQS Queue Enumeration Followed by Attribute Inspection** (`low`) — the
  recon precursor (`ListQueues` → `GetQueueAttributes`). Low-signal alone;
  escalate when the same principal then calls `SetQueueAttributes`.
- **SQS Queue Resource Policy Removed After Modification** (`medium`) — the
  step-5 cleanup (`Policy` cleared to `""`). Correlated with a prior wildcard
  event on the same queue it marks a complete inject-and-cover sequence.

`kql_t1098.kql` carries the Sentinel / Log Analytics equivalents plus a
five-step chain-correlation query that scores a principal CRITICAL when
enumeration, injection and cleanup all appear within the correlation window.

## False positives

SNS→SQS subscription fan-out policies use the SNS service principal, not `"*"`,
so they should not trigger the wildcard rule. IaC deployers (Pulumi, Terraform,
CDK) that legitimately create public queues are filtered by deployer-role ARN
suffix — expand that list to match your environment.

**Severity:** manifest HIGH; matches the IR view.

**GuardDuty:** no finding type specific to this technique.

Full response procedure is in `../PLAYBOOK.md`.
