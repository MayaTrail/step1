# Detection Note — T1580 (Enumerate AWS Environment from EC2 Instance)

**Signal:** an EC2 **instance role** issuing a broad spread of `Describe*` /
`List*` / `Get*` calls across multiple services — especially IAM enumeration,
and especially from an instance that is not a known bastion or operations host.

**The original rule watched the wrong events.** Its selection matched
`ssm.amazonaws.com` (`SendCommand`, `GetCommandInvocation`,
`DescribeInstanceInformation`) while its own description named
`ec2:Describe*` / `s3:ListBuckets` / `iam:ListUsers` as the signal. It watched
the *delivery plumbing* rather than the reconnaissance, which meant:

- an attacker working from a plain shell on the instance was invisible to it
- every legitimate Run Command was a false positive

SSM is now a supporting `low` rule, correlated rather than alerted on.

**Breadth, not volume.** Instance roles normally exercise a small, fixed set of
calls — the app's own API surface. The anomaly is *fan-out*: many distinct
actions across two or more services in a short window. Count distinct
`(eventSource, eventName)` per role, not raw call count.

**Identifying instance roles is essential.** The whole signal is "an instance
role behaving like an operator". The Sigma rules match on a role-name suffix
(`-instance-role` — adjust to your naming); the KQL uses a Sentinel watchlist
named `InstanceRoles`. A stale watchlist silently narrows the detection, so
maintaining it is a standing task, not a one-off.

**Hunting caveat — instance-profile sessions:** CloudTrail
`lookup-events --attribute-key Username` matches the *session name*, which for
an instance profile is the **instance ID**, not the role name. Filter on
`sessionContext.sessionIssuer.userName` instead. In the Sentinel schema the
flattened column is `SessionIssuerUserName` — there is no
`UserIdentitySessionContext` JSON blob to parse.

**Root cause worth noting:** this emulation's own infrastructure attaches
`ReadOnlyAccess` to the instance role. That over-privilege is what makes the
technique work at all, and is the thing the playbook's guardrails target.

**Error strings:** if you extend detection to *failed* recon, denials are not
uniformly formatted across services — EC2 uses `Client.UnauthorizedOperation`;
IAM and S3 use `AccessDenied` / `AccessDeniedException`. Match the
service-appropriate string and confirm against a sample.

**Severity:** the manifest rates this LOW; the IR view is **Medium** — recon
from an instance role signals an active foothold on a host. The tactic label
(*Discovery*) is correct here.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1580.yml` — four documents: IAM-enumeration-from-instance-role
  (`high`), the breadth `value_count` correlation (`high`), its base rule
  (`low`), and the demoted SSM delivery rule (`low`).
- `kql_t1580.kql` — the full breadth detection with multi-service verdict
  logic. Requires the `InstanceRoles` watchlist.

Full response procedure is in `../PLAYBOOK.md`.
