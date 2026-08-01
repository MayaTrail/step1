# Detection Note — T1562.007 (Open Ingress Port 22 on Security Group)

**Signal:** an ingress rule permitting `0.0.0.0/0` or `::/0` to reach an
administrative port (22, 3389) — or all ports.

**Content inspection is the whole detection.** Adding ingress rules is routine.
The port and the CIDR *are* the signal, and an event-name match ignores both —
which is exactly what the original rule did, while also matching
`RevokeSecurityGroupIngress`, the attacker's cleanup rather than the attack.

**Four variants a naive "port 22 + 0.0.0.0/0" match misses:**

1. **Range containment** — `fromPort:20, toPort:23` exposes 22 without ever
   naming it. Check `fromPort <= 22 <= toPort`, not equality.
2. **All ports** — `ipProtocol: "-1"`, or `0–65535`.
3. **IPv6** — `::/0` is exactly as open as `0.0.0.0/0`.
4. **RDP** — 3389 deserves identical treatment to 22.

**Include `ModifySecurityGroupRules`.** The newer API achieves the same
exposure and evades an `Authorize`-only rule.

**Two matching gotchas, both load-bearing:**

- In KQL, use `contains` (substring), **not** `has`. `has` is whole-term and
  CIDR strings contain `.` and `/` delimiters, so `has "0.0.0.0/0"` silently
  never matches.
- Field casing differs by source: CloudTrail `requestParameters` are camelCase
  (`ipPermissions.items[].fromPort`); the `describe-security-groups` response
  is PascalCase (`IpPermissions[].FromPort`). A query written against one shape
  returns nothing against the other.

**Prevention has an IAM limitation worth knowing:**
`ec2:AuthorizeSecurityGroupIngress` is **not conditionable** on the rule's CIDR
or port through IAM. You cannot write a policy that permits SG changes but
forbids world-open ones. Prevention is therefore AWS Config auto-remediation
(the `restricted-ssh` managed rule) plus restricting *who* may change security
groups — not an IAM condition.

**MITRE note:** the technique T1562.007 (*Disable or Modify Cloud Firewall*) is
correct, but its canonical **tactic is Defense Evasion**, while the manifest
tags this emulation "Exfiltration". The rules here carry the Defense Evasion
tag. Severity is HIGH in both the manifest and the IR view — consistent, unlike
most of this set.

**GuardDuty:** `UnauthorizedAccess:EC2/SSHBruteForce` — fires if traffic
follows the exposure, confirming the opening was reachable and found.

**Files here:**
- `sigma_t1562_007.yml` — one rule (`high`). Substring-based and therefore
  approximate; it cannot express range containment.
- `kql_t1562_007.kql` — the authoritative structured check covering all four
  variants above. Deploy this as the real detection.

Full response procedure is in `../PLAYBOOK.md`.
