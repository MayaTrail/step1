# Detection Note — T1654 (Log Enumeration)

**Signal:** reading the CloudTrail logging configuration — specifically the two calls that make
tampering succeed on the first attempt.

## MITRE mapping

`T1654 — Log Enumeration`, Discovery. Verified live 2026-08-31.

## Its identity filter excludes almost every modern principal

The rule matches `userIdentity.type:"IAMUser"`. SSO users, federated identities, EC2 instance roles,
Lambda execution roles and every cross-account access path arrive as **`AssumedRole`**.

So a compromised role session — which is what a cloud intrusion normally looks like — reads the
entire logging configuration without this rule firing once. In most estates that filter discards
nearly all traffic, which is why the KQL projects `IdentityTypes` explicitly: a reviewer can see how
much of their own activity the original would have dropped.

## It watches the least informative read

`DescribeTrails` returns the trail list. The two that matter are:

- **`GetTrailStatus`** — returns `IsLogging`, and with `DescribeTrails` the trail's `HomeRegion`.
- **`GetEventSelectors`** — returns exactly what is and is not being captured.

The `HomeRegion` is the prerequisite for tampering. Both `StopLogging` and `DeleteTrail` are refused
outside it and refused entirely on shadow trails, so an actor either obtains it first or fails
visibly. A rule watching `DescribeTrails` alone catches the more general half and misses the
specific one.

## Configuration reads and content reads are different acts

`FilterLogEvents` is a CloudWatch Logs call, not a CloudTrail one, and the source rule mixes it in.
Reading log **content** works out what the defender already has; reading the **configuration** works
out how to stop them getting more. Both are `T1654`, and they are separated here so the follow-on
differs — a content read points the investigation at what was already recorded, a configuration read
points it at what is about to stop being recorded.

## Response levers

**On its own, this is not an incident.** A single configuration read is unremarkable and ships at
informational for that reason. What makes it valuable is shape: a sweep across Regions, status and
selectors read together, or a read followed by tampering.

**The read-then-tamper pair is the earliest reliable warning available.** It fires before the
trail's state changes in a way any health check would show, and before the refused-attempt rules in
the sibling directories. Where it fires, go straight to those directories rather than treating this
as discovery.

**Denied reads are the cleaner signal.** The successful case has many legitimate explanations —
CSPM tools, compliance scanners, engineers. A principal probing for visibility into the logging
estate *without* the permission has far fewer, and the source rule's success filter discards it.

**Allowlist your scanners deliberately.** A CSPM tool enumerating trails across every Region looks
exactly like the sweep case. Identifying it is a one-off exercise and a useful one, because a
scanner nobody recognises is itself a finding.

**MITRE:** `T1654 — Log Enumeration` (Discovery), verified live 2026-08-30, with `T1685.002` on the
read-then-tamper correlation.

**GuardDuty:** no finding type covers reading the CloudTrail configuration. This is the only
coverage for the reconnaissance step.

**Files here:**
- `sigma_t1654.yml` — five documents: `cloudtrail_audit_config_read` (informational base rule,
  covering `GetTrailStatus` and `GetEventSelectors` and all identity types),
  `cloudtrail_audit_config_read_denied` (medium), `cloudtrail_config_tampered` (informational base
  rule), an `event_count` correlation for five or more reads in ten minutes (medium), and a
  `temporal_ordered` correlation for read-then-tamper (critical).
- `kql_t1654.kql` — rates on the shape of the reads, separates configuration reads from content
  reads, and projects the identity types so the original filter's blind spot is visible in the
  output.

Full response procedure is in `../PLAYBOOK.md`.
