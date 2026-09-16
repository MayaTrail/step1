# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold and immediate rules over query strings, one with a regex |
| Scope captured | Four ingress rules: Ingress Rule Open to 0.0.0.0/0, Security Group Opened to the Internet for Remote Management, Ingress Rule Was Added, Ingress Rule Was Revoked |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

**Decomposed from an aggregated playbook.** Previously four of six rules folded into
`aws.initial-access.sg-remote-management-open`; the two egress rules became
`../../sg.exfiltration.egress-rule-opened/`, because opening an outbound path is a different technique
with a different tactic and a different response.

**Merge test — applied, not assumed.** The four ingress rules become one use case: a general
open-to-the-world rule, a sharpened remote-management form of the same rule, the unfiltered
ingress-added base, and the revoke that closes the pair. They are one operation
(`AuthorizeSecurityGroupIngress`) at increasing specificity, sharing one response. The revoke rule
is kept here rather than given its own directory because a firewall rule being removed is a good
thing happening — its value is entirely as the second half of an open-then-close pair, which is a
correlation, not a use case.

**The `0.0.0.0/0` rule reads only the legacy request shape.** `AuthorizeSecurityGroupIngress` accepts
either top-level flat parameters — `CidrIp`, `FromPort`, `IpProtocol`, all `Required: No` — or the
structured `IpPermissions.N` array. The rule matches `requestParameters.cidrIp`, which exists **only
in the flat form**. AWS states four separate times to *"use IP permissions instead"* for IPv6 or for
multiple rules, and every example in the API reference uses `IpPermissions` — which is what the
console, the CLI and the SDKs emit. The shipped KQL surfaces a `FlatFormUsed` counter precisely so a
reviewer can answer, from one query against their own account, whether the original rule has ever
been able to fire there.

**And the flat form cannot carry IPv6 at all.** *"To specify an IPv6 address range, use IP
permissions instead."* So the rule is IPv4-only by construction, and `::/0` — exactly as open — is
invisible to it.

**A port list does not reach every open SSH port.** `IpProtocol: -1` means all protocols: port 22 is
reachable with no `fromPort: 22` anywhere in the request. AWS adds a sharper case verbatim: *"If you
specify a protocol other than one of the supported values, traffic is allowed on all ports,
regardless of any ports that you specify."* The all-protocols case ships as a sibling block.

**The P1 rule regexes `requestParameters.ipPermissions.items_str`, which is not a CloudTrail field.**
It is a flattened representation produced by an ingestion pipeline — the same portability failure as
an enrichment-only field, and the fifth instance of that class found across this source set.

**Nothing in the pack watches `ModifySecurityGroupRules`.** That API changes an existing rule's CIDR,
ports and protocol with no `Authorize` call at all. Narrowing a rule for a review and widening it
back afterwards produces exactly one event, and no rule in the source pack sees it.

**The two ingress rules group by different fields.** `Ingress Rule Was Added` groups by
`userIdentity.sessionContext.sessionIssuer.userName` — the role name — while `Ingress Rule Was
Revoked` groups by `userIdentity.arn` — the session. Sibling rules over the same resource, grouped at
two different granularities, for no stated reason.

**MITRE:** the source maps these rules to **nothing**. `T1686.001 — Disable or Modify System
Firewall: Cloud Firewall` for the firewall change, with `T1133 — External Remote Services` for the
remote-management exposure. Both verified live 2026-08-30.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `sg.*` playbook is in `../../_ground-truth/sg.md`, audited 2026-08-30.
