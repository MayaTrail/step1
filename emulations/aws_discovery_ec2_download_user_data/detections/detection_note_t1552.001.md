# Detection Note: T1552.001 (Download EC2 Instance User Data)

**Signal:** `ec2:DescribeInstanceAttribute` with `attribute=userData` across
many distinct instances, by a principal with no operational need to read them.

**`attribute=userData` is the discriminator.** `DescribeInstanceAttribute` is
called for many benign attribute types. A rule without this filter fires
constantly on activity unrelated to credential harvesting.

**Breadth is the signal.** One user-data read is administration; five or more
distinct instances in ten minutes is harvesting. Count distinct `instanceId`
per principal, event-counting cannot express the technique.

**`DescribeInstances` is not a trigger.** It is among the highest-volume calls
in AWS, every console load and inventory tool emits it. It has been dropped as
a selector entirely. Use `DescribeInstances` → `DescribeInstanceAttribute
(userData)` as a *sequence* signal if you want the enumeration context.

**Why this matters:** user-data frequently contains bootstrap credentials,
configuration secrets, and provisioning tokens. It is readable through a plain
control-plane API with no host access, which makes it a quiet and effective
credential source.

**Error strings:** EC2 CloudTrail errors carry a `Client.` prefix, a
permission denial is `Client.UnauthorizedOperation`, not
`UnauthorizedOperation`. Match the prefixed form or use `contains`, and confirm
against a sample event.

**MITRE note:** the manifest tags the tactic as *Discovery*, but T1552.001 is
canonically a Credential Access technique (TA0006). The behaviour is genuinely
dual, enumeration in service of credential theft, but the tactic label is
imprecise.

**Severity:** the manifest rates this LOW; the IR view is **Medium**, the
payoff is conditional on what the user-data actually contains, but when it
contains secrets the disclosure is complete and silent.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1552.001.yml`, two documents: the userData base rule (`low`, not for
  direct alerting) and the `value_count` breadth correlation (`high`).
- `kql_t1552.001.kql`, the same breadth detection for log platforms.

Full response procedure is in `../PLAYBOOK.md`.
