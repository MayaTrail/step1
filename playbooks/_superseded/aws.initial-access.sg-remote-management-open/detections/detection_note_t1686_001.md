# Detection Note — T1686.001 / T1133 (Security Group Opened to the Internet)

**Signal:** an EC2 security group ingress rule is created — or an existing one edited —
whose source is a `/0` prefix and whose **port range spans** a remote-management or
database port, or whose protocol is `-1`.

**The port range is the discriminator, not the port value.** This is the whole technique
in one sentence, and it is the thing every rule in this family gets wrong. An ingress
rule of `fromPort: 0, toPort: 65535` exposes SSH without the number 22 appearing anywhere
in the event. `fromPort: 1, toPort: 1024` does the same. `ipProtocol: "-1"` opens every
port on every protocol and carries **no port fields at all**. A rule that matches
`fromPort: 22` catches the careful attacker who opened exactly one port and misses all
three of the careless ones — which is the wrong way round.

**What the original rules got wrong.** The P1 rule matches the literal integer in
`fromPort` against `(22|3389|5985|5986)`, correlates the port and the CIDR as two
independent substring searches over the *whole* serialized permission array rather than
within one element, has no `errorCode` filter, and never reads `ipv6Ranges`. The P2 rule
reads `requestParameters.cidrIp` — a real request parameter, but only for the flattened
submission form, so it yields null on every call made with `--ip-permissions`. And the
set alerts on `RevokeSecurityGroupIngress` at P4: a rule removal is remediation, not
exposure.

## The three shapes one API produces

`AuthorizeSecurityGroupIngress` accepts two mutually exclusive request forms, and the
CIDR lives in a different place in each:

```
ARRAY form   requestParameters.ipPermissions.items[].ipRanges.items[].cidrIp
             requestParameters.ipPermissions.items[].ipv6Ranges.items[].cidrIpv6
             ...with fromPort / toPort / ipProtocol on the items[] element itself

FLAT form    requestParameters.cidrIp
             requestParameters.fromPort / .toPort / .ipProtocol
```

Two `items` wrappers, not one. A flat path against the array shape returns `null`
silently — no error, no match, a clean-looking queue. And in the flat form `ipPermissions`
is **still present, as an empty object**, so testing for its existence does not tell the
shapes apart — only the absence of `ipPermissions.items` does. The two never both resolve
on one event, so in Sigma they must be **sibling blocks ORed in the condition** (here,
separate rule documents), never two keys in one block: keys inside a block are ANDed, and
ANDing two paths that cannot both resolve is a rule that never fires. That is the same defect shape as ANDing
`policyDocument` and `assumeRolePolicyDocument` in the `iam_role_trust_backdoor` family.

The third shape is a different API entirely. **`ModifySecurityGroupRules`** edits an
existing rule in place, so a rule already permitting `10.0.0.0/8` on port 22 can be
widened to `0.0.0.0/0` with **no `AuthorizeSecurityGroupIngress` event ever emitted**.
Every rule keyed on the authorize event is blind to it. Its CloudTrail rendering is
unlike the others — the XML request wrapper survives and the keys are PascalCase:

```
requestParameters.ModifySecurityGroupRulesRequest.SecurityGroupRule.SecurityGroupRule.CidrIpv4
```

That path is corroborated from real events and from an AWS-published CloudTrail Lake sample
query, but is **not specified in the API reference**. The inner `SecurityGroupRule` is an
object for one rule and an array for several. Confirm both against a real event in your own
trail before relying on them.

## Match the prefix length, not the string

`0.0.0.0/0` is the canonical form, but AWS **canonicalizes CIDRs on the way in**:
`1.2.3.4/0` is accepted and becomes `0.0.0.0/0` in the resulting rule. `requestParameters`
records what the client *sent*, so an equality against the literal `0.0.0.0/0` misses the
non-canonical submission while the rule it created is fully open.

Matching the prefix length closes that, and it is not a loosening — no other prefix length
ends in `/0`:

```
0.0.0.0/0      ends with "/0"    MATCH
1.2.3.4/0      ends with "/0"    MATCH   (canonicalizes to 0.0.0.0/0)
::/0           ends with "/0"    MATCH
10.0.0.0/10    ends with "10"    no
192.168.0.0/20 ends with "20"    no
```

One operator, both address families, and the non-canonical form comes along for free.
`|endswith` in Sigma and `endswith` in KQL — never `has`, which is whole-term matching and
breaks on every character in a CIDR.

## What no Sigma rule can do here

Sigma has no numeric comparison and no way to correlate two fields *within the same array
element*. Two questions decide whether an ingress rule is this technique, and neither is a
substring question:

1. **Does the port range contain the management port?** `fromPort <= 22 <= toPort` is
   arithmetic. Sigma cannot express it.
2. **Do the open CIDR and the spanning range belong to the same `ipPermissions` element?**
   A single call adding 443 to `0.0.0.0/0` and 22 to the corporate CIDR satisfies a
   world-open block and a port block from *different* elements and fires a false positive.

`sigma_t1686_001.yml` approximates (1) by enumerating the range **starts** an operator
actually sends — `0` and `1` for the sweeps, plus the management and database ports
themselves for the single-port case — and cannot address (2) at all. `kql_t1686_001.kql`
does both exactly: `mv-expand` down to one permission element, `mv-apply` the port list
against `EffFrom <= port <= EffTo` inside it. The playbook's queries do the same through
the shared `tools/sg_open_rule_test.py`, which normalises all three request shapes and
carries a `--self-test` battery of the must-fire and must-not-fire cases.
**Treat a Sigma hit as the trigger for the range test, not as a disposition.** That
split is the same shape as the substring-rule-plus-decode pairing in the
`iam_inline_escalation_primitive_granted` note.

The residual gap in the Sigma approximation is a range that starts at a value not on the
list and still spans a port — `fromPort: 20, toPort: 30` reaches SSH and matches no
enumerated start. Nothing in Sigma closes it; the KQL and the investigation query do.

## The grant is not the exposure

This is the claim most easily overstated, and a playbook that declares compromise on the
CloudTrail event alone is wrong. A security group has effect only on the resources it is
**associated with**. For internet traffic to actually arrive, all four must hold:

```
1. the security group is attached to an ENI          (empty describe-network-interfaces = attached to nothing)
2. that resource has a public IPv4/EIP or an IPv6 GUA
3. the subnet's route table sends 0.0.0.0/0 to an internet gateway
4. the subnet's network ACL permits the port inbound AND the ephemeral range outbound
```

Two of those checks have an inverted-default trap, and both produce a confident wrong
answer if you read empty output as "no":

- A subnet with **no explicit route-table association** is implicitly associated with the
  VPC **main route table**, and the `association.subnet-id` filter returns *nothing* for
  it. Empty output means "go read the main table", never "no route to the internet".
- A subnet with **no explicit NACL association** uses the **default** NACL, which
  **allows all traffic in and out**. Absence of an association is allow-all, not deny-all.

Conversely, "it's only a security group change" understates it: if all four hold, the port
was reachable from the entire internet from the moment the rule landed, and the exposure
window is the interval to the matching revoke. The playbook's Query 3 runs all four checks
through `tools/sg_reachability.sh` and prints one verdict per attached interface; VPC
Reachability Analyzer settles it authoritatively for IPv4 —
though it models configuration and **does not send packets**, so it proves the path is
open, not that anything used it.

## Response levers

**Contain by rule ID, not by re-specifying the rule.**
`responseElements.securityGroupRuleSet.items[]` carries the `securityGroupRuleId` of each
rule the call created. `revoke-security-group-ingress --security-group-rule-ids sgr-...`
removes exactly that rule and nothing else. Re-specifying protocol/port/CIDR instead risks
removing a different rule that happens to match, or silently removing nothing.

**`describe-security-groups` does not return rule IDs** — it returns `IpPermissions`.
`describe-security-group-rules` returns `SecurityGroupRule` objects with
`securityGroupRuleId`, `cidrIpv4`, `cidrIpv6`, `fromPort`, `toPort`, `ipProtocol` and
`isEgress`. Reach for the second one whenever you need a handle to revoke.

**Revoking the rule does not undo the exposure.** Anything that connected during the
window already has whatever it obtained. The rule removal closes the door; it does not
evict what came through it, and it does not rotate the credentials on the host.

**There is no IAM condition key for the CIDR.** The authorization context for
`ec2:AuthorizeSecurityGroupIngress` carries `aws:ResourceTag`, `ec2:ResourceTag`,
`ec2:SecurityGroupID` and `ec2:Vpc` — nothing about the rule's content. No SCP can deny
`0.0.0.0/0` on port 22 while permitting the same call on a narrow CIDR. A guardrail
written that way is a no-op that reads as protection. The preventative control that does
work is **VPC Block Public Access**, which sits above the security group, NACL and route
table and holds regardless of what rule someone writes.

**Error strings:** EC2 prefixes its CloudTrail error codes with `Client.` —
`Client.UnauthorizedOperation` for the IAM denial, plus `Client.InvalidGroup.NotFound`,
`Client.InvalidPermission.Duplicate`, `Client.InvalidPermission.Malformed`,
`Client.InvalidParameterValue` and `Client.RulesPerSecurityGroupLimitExceeded` on the same
path. The unprefixed forms are SDK error codes and match nothing in a trail. Match
prefix-tolerantly with `contains` and confirm against a real denied event. Only the
`UnauthorizedOperation` family is a denial — the rest are malformed or duplicate requests
and must not be counted as probing.

**Evidence ceiling:** `requestParameters` has a documented maximum of **100 KB**, above
which CloudTrail omits the field content. Every content rule here reads a path inside it,
so the Sigma file ships a companion on the omission marker. Reaching that ceiling on this
API needs many ranges with long descriptions in one call and a raised
rules-per-security-group quota — unlikely, but a total evasion rather than a partial one.

**MITRE:** the source set tags this alert `T1686.001` (*Impair Defenses: Disable or Modify
Cloud Firewall*) with tactic **Defense Impairment**, and tags its sibling CIDR alert `T1133`
(*External Remote Services*) with **Initial Access**. Both are right, and they are right
about *different halves of the same event*: modifying the cloud firewall is T1686.001, and
what the modification enables — an externally reachable management service — is T1133.
This directory carries both tags on the exposure rules.
Mapping-precision notes on the two low-priority rules, not operational defects on the two
that matter.

**Severity:** the source rates the remote-management case **P1** and the bare `0.0.0.0/0`
case **P2**. IR view: **High, P0** for a `/0` rule spanning a management or database port
on an *attached* group in a public subnet, because the exposure is live at the moment the
rule lands and needs no further attacker action. **Medium** where the group is unattached
or the subnet has no internet-gateway route — real misconfiguration, not a live incident,
and the difference is four API calls. The P1/P2 split in the source is directionally
right; what is missing is the reachability check that decides which of the two you have.

**GuardDuty:** **no finding type detects the configuration change** — there is no
`Policy:EC2/*` family at all. GuardDuty sees only the consequences, and only from VPC Flow
Logs, so **not over IPv6**: `Recon:EC2/PortProbeUnprotectedPort` (not raised for ports 80
and 443; High severity for 9200/9300), `UnauthorizedAccess:EC2/SSHBruteForce`,
`UnauthorizedAccess:EC2/RDPBruteForce`, `Impact:EC2/WinRMBruteForce`. Any of these landing
after one of these events is confirmation the exposure was found and used — a severity
escalation, never the detection.

**AWS Config**, detective and complementary, all three evaluating the group in isolation
without knowing whether it is attached: `restricted-ssh` (identifier
`INCOMING_SSH_DISABLED`), `restricted-common-ports` (identifier
`RESTRICTED_INCOMING_TRAFFIC`, whose default blocked ports are **20, 21, 3389, 3306,
4333** — port 22 is **not** among them and must be added), and
`vpc-sg-open-only-to-authorized-ports` (`VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS`).

**Files here:**
- `sigma_t1686_001.yml` — six documents: the world-open management-port rule for the
  **nested** request shape (`high`) and the same rule for the **flat** shape (`high`,
  and not optional — which one fires depends on how the caller was written), the
  world-open any-port catch-all (`medium`), the `ModifySecurityGroupRules` in-place
  widening (`high`), the `requestParameters`-omitted companion (`medium`), and the denied
  security-group-write base rule (`low`) with its volume correlation (`medium`).
- `kql_t1686_001.kql` — the exact range-containment test, element-scoped, plus the
  exposure-window companion that uses `RevokeSecurityGroupIngress` as a correlation
  partner rather than as a signal, the `ModifySecurityGroupRules` companion, and the
  reachability, error-string and prevention guidance inline.

Full response procedure is in `../PLAYBOOK.md`.
