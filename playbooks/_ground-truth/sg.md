# EC2 Security Groups — verified service behaviour

Audited 2026-08-30 against AWS documentation. Every claim below is quoted or directly derived from
a cited page. Shared by every `sg.*` playbook; do not restate it in each one.

Source: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html

---

## 1. There are two request shapes, and the flat one cannot express IPv6 or multiple rules

`AuthorizeSecurityGroupIngress` accepts either **top-level flat parameters** — `CidrIp`, `FromPort`,
`ToPort`, `IpProtocol`, all `Required: No` — or the structured **`IpPermissions.N`** array. AWS
repeats the same guidance on four of the flat parameters:

> To specify an IPv6 address range, **use IP permissions instead**.
> To specify multiple rules and descriptions for the rules, **use IP permissions instead**.

All three examples in the API reference use `IpPermissions.N`, including the simplest.

Consequences for detection, and they are severe:

- A rule keyed on `requestParameters.cidrIp` reads **only the flat form**. Anything submitted as
  `ipPermissions` — which is what the console, the CLI and every SDK produce for a multi-rule or
  IPv6 request — has no top-level `cidrIp` at all.
- A rule keyed on the flat form is **IPv4-only by construction**, because IPv6 cannot be expressed
  there. `::/0` is exactly as open as `0.0.0.0/0` and lives at
  `ipPermissions.items[].ipv6Ranges.items[].cidrIpv6`.
- A correct rule must read **both** shapes. Reading one is not a partial detection; it is a
  detection that misses whichever shape the estate's tooling happens to emit.

## 2. `0.0.0.0/0` is not the only way to be open

- **`IpProtocol: -1` means all protocols.** A rule opening all protocols to a CIDR opens port 22
  without `fromPort: 22` appearing anywhere. Any port-list match misses it.
- Worse, verbatim: *"If you specify a protocol other than one of the supported values, traffic is
  allowed on all ports, regardless of any ports that you specify."* An unrecognised protocol value
  opens everything while carrying port fields that look restrictive.
- **Two rules cover the internet**: `0.0.0.0/1` plus `128.0.0.0/1`. Neither string matches a
  `0.0.0.0/0` test, and together they are identical in effect.
- **A prefix list or a source security group is a third and fourth source type.** AWS: *"You must
  specify exactly one of the following sources: an IPv4 or IPv6 address range, a prefix list, or a
  security group."* A managed prefix list can contain `0.0.0.0/0`, and the ingress event names only
  the prefix list ID.
- **A source-security-group rule with no protocol grants everything.** On `SourceSecurityGroupName`
  and `SourceSecurityGroupOwnerId`: *"The rule grants full ICMP, UDP, and TCP access."*

## 3. AWS canonicalizes CIDRs, which changes what a string match sees

> AWS canonicalizes IPv4 and IPv6 CIDRs. For example, if you specify 100.68.0.18/18 for the CIDR
> block, AWS canonicalizes the CIDR block to 100.68.0.0/18. Any subsequent DescribeSecurityGroups
> and DescribeSecurityGroupRules calls will return the canonicalized form.

`0.0.0.0/0` is already canonical so this does not affect the open-to-the-world case directly, but it
does mean a rule comparing a CIDR string from a `Describe` call against one from a CloudTrail
request parameter can be comparing two different spellings of the same range.

## 4. `ModifySecurityGroupRules` changes an existing rule and is a different event

Source: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySecurityGroupRules.html

> Modifies the rules of a security group.

It takes `GroupId` and `SecurityGroupRule.N`, and it can change an existing rule's CIDR, ports and
protocol **without any `Authorize` call**. A rule set scoped to `AuthorizeSecurityGroupIngress` and
`AuthorizeSecurityGroupEgress` does not see it. Narrowing a rule to a corporate CIDR and later
widening it back to `0.0.0.0/0` produces exactly one `ModifySecurityGroupRules` event and nothing
else.

## 5. Egress is a real exfiltration path and is usually unrated

`AuthorizeSecurityGroupEgress` opening `0.0.0.0/0` on all ports gives every instance in the group an
unrestricted outbound path. It is the same class of finding as an open ingress rule and is
frequently carried as a building block rather than as a detection — which is how it survives review.

## 6. Rule changes are near-immediate

> Rule changes are propagated to instances associated with the security group as quickly as
> possible. However, a small delay might occur.

There is no approval step and no meaningful propagation window to intervene in. Detection is
after-the-fact by construction, which is why the preventive control (an SCP, or a
`ModifySecurityGroupRules`-aware guardrail) matters more here than in services where a second act is
required.

---

## MITRE currency, verified 2026-08-30

| ID | Status | Name | Tactic |
|---|---|---|---|
| `T1686` | live | Disable or Modify System Firewall | Defense Impairment |
| `T1686.001` | live | Disable or Modify System Firewall: Cloud Firewall | Defense Impairment |
| `T1133` | live | External Remote Services | Initial Access / Persistence |
| `T1021` | live | Remote Services | Lateral Movement |

`T1686.001 — Cloud Firewall` is the correct mapping for widening a security group.
