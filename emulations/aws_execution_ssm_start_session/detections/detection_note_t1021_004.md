# Detection Note — T1021.004 (Open SSM Sessions to Multiple EC2 Instances)

**Signal:** `ssm:StartSession` from a non-operator principal, across several
distinct instances, or using a port-forwarding document.

## The single most important fact

**Session content is never in CloudTrail.** CloudTrail records that a session
*began* — not a keystroke of what happened inside it. There is no verbosity
setting that changes this. The only source of session content is **Session
Manager logging** (S3 or CloudWatch Logs), configured through the
`SSM-SessionManagerRunShell` document's `inputs`.

The consequence for response is severe: if Session Manager logging was not
configured, a confirmed intrusion is **unrecoverable by investigation**. There
is no way to determine what was done. The only defensible assumption is full
compromise of every instance touched, and the only safe remediation is rebuild.

Two things follow:

- Enabling Session Manager logging is a **prerequisite**, not a hardening
  nicety. It is the difference between an investigation and a rebuild.
- **Disabling that logging is itself a detection.** Watch for the
  `s3BucketName` / `cloudWatchLogGroupName` inputs being cleared on the
  `SSM-SessionManagerRunShell` document, especially shortly before a session.

## Discriminators

| Signal | Why it matters |
|---|---|
| Non-operator principal | `StartSession` is a normal operator action; the allowlist is what makes the rule deployable |
| Fan-out (≥3 distinct targets) | One instance is administration; several is fleet access |
| Port-forwarding document | A **pivot**, not a shell — see below |

**Port forwarding deserves its own severity.** `AWS-StartPortForwardingSession`
(and `…ToRemoteHost`) turns Session Manager into a tunnel into the VPC,
reaching services never meant to be exposed. It bypasses security groups
entirely, because the traffic is outbound from the instance's SSM agent. The
original rule treated it identically to a shell session.

**Why this technique is attractive to an attacker:** full interactive access
with no SSH, no key material, no inbound security-group rule, and no network
path from the internet. Nothing about it looks like a traditional intrusion.

**Error strings:** SSM denials surface as `AccessDeniedException`; an
unreachable target as `TargetNotConnected`. SSM service errors are **not**
`Client.`-prefixed like EC2 errors.

**MITRE note:** the manifest maps T1021.004 (*Remote Services: SSH*), but
Session Manager is **not SSH** — no SSH daemon, no key exchange, no port 22.
The precise mapping is **T1021.008** (*Direct Cloud VM Connections*). Both tags
are carried on the rules; the T1021.004 mapping is inherited from the upstream
catalogue.

**Severity:** manifest MEDIUM; IR view **High** — unlogged interactive access
across a fleet.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1021_004.yml` — four documents: non-operator session (`high`),
  port-forwarding (`critical`), the fan-out `value_count` correlation
  (`high`), and its base rule (`low`).
- `kql_t1021_004.kql` — all three signals in one query, plus a note on
  alerting when Session Manager logging is disabled.

Full response procedure is in `../PLAYBOOK.md`.
