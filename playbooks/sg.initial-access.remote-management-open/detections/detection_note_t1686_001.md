# Detection Note — T1686.001 (Disable or Modify System Firewall: Cloud Firewall)

**Signal:** an ingress rule opening a security group to the internet — read from whichever of the
two request shapes the caller happened to use.

## The `0.0.0.0/0` rule reads only the legacy shape

`AuthorizeSecurityGroupIngress` takes either flat top-level parameters — `CidrIp`, `FromPort`,
`IpProtocol` — or the structured `IpPermissions.N` array. The source rule matches
`requestParameters.cidrIp`, which exists **only in the flat form**.

AWS says four separate times to *"use IP permissions instead"*, and every example in the API
reference uses it. The console, the CLI and the SDKs emit the structured form for anything but a
single IPv4 rule.

The shipped KQL surfaces a **`FlatFormUsed`** counter for exactly this reason: if it reads zero
across a month while open-to-the-world rules were created, then every one of them was submitted
structured, and the original rule has never fired in that account and never will. That is a
one-query answer to "is our existing detection working", and it is worth running before anything
else here.

## The flat form cannot carry IPv6

> *"To specify an IPv6 address range, use IP permissions instead."*

So the source rule is IPv4-only by construction. `::/0` is exactly as open as `0.0.0.0/0`, and it
lives at `ipPermissions.items[].ipv6Ranges.items[].cidrIpv6`.

## A port list does not reach every open SSH port

`IpProtocol: -1` means **all protocols** — port 22 is reachable with no `fromPort: 22` anywhere in
the request, so any port-list match misses it. AWS states a sharper case verbatim:

> *"If you specify a protocol other than one of the supported values, traffic is allowed on all
> ports, regardless of any ports that you specify."*

An unrecognised protocol value opens everything while carrying port fields that look restrictive.
Both are covered by the all-protocols sibling block.

## Response levers

**`ModifySecurityGroupRules` is the blind spot to close first.** It changes an existing rule's CIDR
and ports with no `Authorize` call, so narrowing a rule for a review and widening it back afterwards
produces exactly one event that the source pack watches nowhere for.

**Revoking is instant and so was the exposure.** AWS: *"Rule changes are propagated to instances
associated with the security group as quickly as possible."* There is no approval step to intervene
in, which is why the SCP in §4 matters more here than the detection does.

**Check the flow logs for the window, not just the rule.** The rule says the door was open; VPC flow
logs say whether anything came through it. That is a different data source with a different
retention, and it is the only evidence of use.

**A prefix list hides the CIDR.** AWS: the source may be *"an IPv4 or IPv6 address range, a prefix
list, or a security group"*. A managed prefix list can contain `0.0.0.0/0` while the event names only
the list ID — `GetManagedPrefixListEntries` is what resolves it, and no rule here can.

**MITRE:** the source maps these rules to **nothing**. `T1686.001 — Disable or Modify System
Firewall: Cloud Firewall` with `T1133 — External Remote Services`, both verified live 2026-08-30.

**GuardDuty:** `Recon:EC2/PortProbeUnprotectedPort` fires when an exposed port is actually probed
from the internet, which is the consequence rather than the change. It needs VPC flow logs and it
does not fire on the configuration event, so these rules are the earlier signal and the two are
complementary.

**Files here:**
- `sigma_t1686_001.yml` — five documents: `sg_remote_management_open_to_internet` (critical, both
  request shapes, both address families, plus the all-protocols case), `sg_ingress_open_to_internet`
  (high), `sg_rule_modified` (high, the `ModifySecurityGroupRules` gap), `sg_ingress_revoked`
  (informational base rule), and a `temporal_ordered` correlation for opened-then-closed (high).
- `kql_t1686_001.kql` — reads both request shapes, counts flat-form usage as a coverage test, and
  states inline the three things it still cannot see: same-entry scoping, split CIDRs, and prefix
  lists.

Full response procedure is in `../PLAYBOOK.md`.
