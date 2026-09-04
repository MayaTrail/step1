# Detection Note — T1686.001 (Disable or Modify System Firewall: Cloud Firewall)

**Signal:** outbound access being re-widened — not merely opened, because open is where every
security group starts.

## The default is already fully open, which inverts the obvious rule

> *"When you first create a security group, it has an outbound rule that allows all outbound traffic
> from the resource. You can remove the rule and add outbound rules that allow specific outbound
> traffic only. If your security group has no outbound rules, no outbound traffic is allowed."*

So `AuthorizeSecurityGroupEgress` opening `0.0.0.0/0` is often **not** a weakening. It is frequently
tooling restating a state that was never removed, and rating it high produces a stream of alerts
about groups being returned to their birth configuration.

The event that matters is the **re-widening** of a group somebody deliberately narrowed — visible
only as a revoke followed by an authorize. A group has restricted egress only because a human chose
that, so undoing it reverses a decision rather than restoring a default. That correlation is the
routable output here; the single event ships at medium.

## The bigger finding is an absence, and no rule can carry it

A security group nobody ever hardened allows all outbound traffic and generates **no CloudTrail
event at all**, because nothing happened. That is the common case in most estates and it is
invisible to every detection by construction.

It is a posture question, answered by `describe-security-group-rules`: any `IsEgress=true` rule with
`CidrIpv4: 0.0.0.0/0` and `IpProtocol: -1` is the default, unremoved. Running that sweep once will
usually find more unrestricted egress than every alert in this directory will over a year.

## Response levers

**Establish whether the group had narrowed egress before.** That single question separates a restored
default from a reversed decision, and it is the whole triage. The rule history is in CloudTrail; the
current state is in `describe-security-group-rules`.

**Removing all egress rules blocks all outbound traffic.** AWS is explicit, and it is the actual
containment action — but on a workload that needs outbound access it is an outage. Narrowing to the
required destinations is the safe form and it is slower.

**Security groups cannot restrict DNS to the VPC resolver.** AWS: *"Security groups cannot block DNS
requests to or from the Route 53 Resolver."* DNS-based exfiltration is outside what any egress rule
can influence — Route 53 Resolver DNS Firewall is the control, and this playbook cannot substitute
for it.

**`ModifySecurityGroupRules` changes a destination with no `Authorize` event.** The same blind spot
as on the ingress side, and nothing in the source pack watches it.

**MITRE:** the source maps these rules to **nothing**. `T1686.001 — Disable or Modify System
Firewall: Cloud Firewall`, verified live 2026-08-30.

**GuardDuty:** no finding type covers security group egress configuration. The behavioural findings
that would follow an outbound path being used — `Backdoor:EC2/C&CActivity.B`,
`Trojan:EC2/DropPoint`, `Behavior:EC2/TrafficVolumeUnusual` — are driven by VPC flow logs and DNS
logs, and they fire on the traffic rather than on the rule. Complementary, and later.

**Files here:**
- `sigma_t1686_001.yml` — three documents: `sg_egress_opened_to_internet` (medium, deliberately not
  higher because the default is open), `sg_egress_revoked` (informational base rule), and a
  `temporal_ordered` correlation for narrowed-then-re-widened (high), which is the routable output.
- `kql_t1686_001.kql` — distinguishes a restored default from a reversed decision, and states
  inline the two things it cannot see: cross-account referenced groups, and DNS to the VPC resolver.

Full response procedure is in `../PLAYBOOK.md`.
