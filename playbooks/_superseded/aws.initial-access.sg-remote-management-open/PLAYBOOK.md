# IR Playbook: Security Group Opened to the Internet — Remote Management Exposed via `ec2:AuthorizeSecurityGroupIngress`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Initial access / Cloud firewall modification (an ingress rule admits the entire internet to a port range that reaches SSH, RDP, WinRM or a database engine) |
| Threat Actor | N/A — single-technique, not actor-attributed |
| Platform | aws |
| Severity | **High, P0** when the rule lands on a security group attached to a resource with a public address in an internet-gateway-routed subnet: the listening service is reachable from every host on the internet from the moment the API returns, with no further attacker action required, and internet-wide scanners find a newly opened SSH or RDP port in minutes. **Medium** when the group is attached to nothing, or the subnet has no route to an internet gateway — a real misconfiguration, not a live incident. The difference between the two is four read-only API calls, and Query 3 makes it. The source set rates the remote-management case P1 and the bare `0.0.0.0/0` case P2; that split is directionally right, and what it is missing is the reachability check that decides which one you actually have |
| MITRE Tactics | Defense Impairment, Initial Access |
| MITRE Techniques | T1686.001, T1133 |
| Services in Scope | EC2 (security groups, network interfaces, route tables, network ACLs), VPC (Flow Logs, Block Public Access, Reachability Analyzer), CloudTrail, GuardDuty, AWS Config, IAM, SSM, plus every service whose listener the exposed range reaches |

**What the technique does:** the actor calls `ec2:AuthorizeSecurityGroupIngress` against a
security group it can already modify, supplying `0.0.0.0/0` or `::/0` as the source and a port
range that reaches a remote-management service — without ever naming the port. `fromPort: 0,
toPort: 65535` opens everything, `fromPort: 1, toPort: 1024` every privileged port, and
`ipProtocol: "-1"` every port on every protocol while carrying no port fields at all; each
exposes SSH with no `22` in the event. A second route reaches the same outcome through a
different API: `ec2:ModifySecurityGroupRules` edits an existing rule in place, so a rule
already permitting `10.0.0.0/8` on port 22 becomes `0.0.0.0/0` with **no
`AuthorizeSecurityGroupIngress` event ever emitted**.

**Why this is potent, and why the usual reflexes miss it.** The reflex is to look for the
port number, and the port number is not there — every rule in this family, both of the source
set's included, matches `fromPort` against a literal list, catching the careful actor who opened
one port and missing all three careless ones. That is backwards: the wide range is the more
damaging outcome *and* the one a hurried actor sends. The second reflex is the console, where
`0-65535` renders as "All TCP" and reads as unremarkable beside the load-balancer rules. The third
is to file this as configuration drift rather than an intrusion, because nothing was created and no
credential issued — but a listening service reachable from the internet *is* an access path, and
the gap to the first scanner connection is minutes.

**Detection is the port RANGE spanning a management port on a `/0` source, computed as a
range-containment test, not a literal port match** — `fromPort <= P <= toPort` for some
management or database port `P`, or protocol `-1`, with both halves read from the *same*
`ipPermissions` element. The source set's P1 rule matches `"fromPort":(22|3389|5985|5986)` and
`"cidrIp":"0.0.0.0/0"` as two independent regexes over the whole serialized permission array,
so it misses every wide range and fires on the routine call opening 443 to the world and 22 to
the office (§2).

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- CloudTrail multi-region trail capturing EC2 **management** events.
  `AuthorizeSecurityGroupIngress`, `RevokeSecurityGroupIngress`, `ModifySecurityGroupRules` and
  `CreateSecurityGroup` are all management events on a default trail — there is no
  security-group data-event type to enable. They are **regional**: query per region
- The CIDR arrives in one of **two mutually exclusive request shapes** and a path for one
  returns `null` on the other with no error: the array form
  `ipPermissions.items[].ipRanges.items[].cidrIp` (two `items` wrappers) or the flattened
  `requestParameters.cidrIp`. `responseElements.securityGroupRuleSet.items[]` carries the
  `securityGroupRuleId` that makes containment surgical. §6's Technique Reference lists the
  full set of silent field-shape traps — read it before writing any query on these events
- **VPC Flow Logs** on every VPC, delivered somewhere a responder can query in the first hour.
  Default v2 format: field 4 `srcaddr`, field 7 `dstport`, field **13 `action`**
  (ACCEPT/REJECT), field 14 `log-status`
- **GuardDuty** — no finding for the configuration change, but its flow-log-derived findings are
  how you learn the exposure was found and used. **AWS Config** with the three security-group
  rules named in §6 is the detective baseline for exposure older than CloudTrail retention

**Alerting (must be pre-configured)**
- **`AuthorizeSecurityGroupIngress` creating a `/0` rule whose port range spans a remote-management or database port, or whose `ipProtocol` is `-1` → P0**
- **`ModifySecurityGroupRules` widening an existing rule's source to a `/0` prefix → P0**
- **A `/0` management-port rule on a group attached to an ENI with a public address in an internet-gateway-routed subnet — the full reachability path confirmed → P1**
- **A GuardDuty `Recon:EC2/PortProbeUnprotectedPort` or SSH/RDP/WinRM brute-force finding on a host behind a security group changed in the last 24 hours → P1**

**Response Tooling**
- AWS CLI v2 with break-glass responder credentials, separate from any principal under
  investigation and specifically not the principal that opened the rule
- `jq`; `awk` for flow-log fields; `python3` and `bash` for the shared
  `tools/sg_open_rule_test.py` (range containment) and `tools/sg_reachability.sh`
- **SSM Session Manager** access to the exposed hosts — it depends on the instance's *outbound*
  443 and is therefore unaffected by anything done to ingress rules in §3
- The security-group baseline from `describe-security-group-rules`, which returns per-rule IDs
  — `describe-security-groups` does not

**Known IOC Baselines**
- Which principals may call `ec2:AuthorizeSecurityGroupIngress` at all — in most accounts one
  IaC deployment role and one break-glass role, everything else an incident
- Your public-facing groups and their legitimate `/0` ports (80 and 443, and nothing else in
  most estates), so a `/0` on any other port is signal without tuning; and your corporate egress
  CIDRs, since a management-port rule sourced from them is the pattern this technique imitates

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `AuthorizeSecurityGroupIngress` creating a `/0` rule whose port range **spans** a remote-management or database port, or whose `ipProtocol` is `-1` | CloudTrail (management) | T1686.001 |
| P0 | `ModifySecurityGroupRules` widening an existing rule's source to a `/0` prefix — emits no authorize event | CloudTrail (management) | T1686.001 |
| P1 | A `/0` management-port rule on a group attached to an ENI with a public address in an internet-gateway-routed subnet — full reachability path confirmed | CloudTrail + EC2 describe API | T1133 |
| P1 | GuardDuty `Recon:EC2/PortProbeUnprotectedPort` or an SSH/RDP/WinRM brute-force finding on a host behind a security group changed in the last 24 hours | GuardDuty | T1133 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | A `/0` ingress rule on any other port — the catch-all; ports 80 and 443 are the dominant benign case | CloudTrail (management) | T1133 |
| P2 | Four or more security-group write calls denied (`Client.UnauthorizedOperation`) for one principal in ten minutes — boundary mapping | CloudTrail (management) | T1686.001 |
| P3 | An AWS Config security-group rule (§6) NON_COMPLIANT on a group with no recent CloudTrail change — pre-existing exposure, not this incident | AWS Config | T1133 |

### Detection Rule Quality Notes

The source rules match the port value instead of the port range, read the CIDR at a path
that resolves for only one of the two request shapes, correlate port and CIDR across
unrelated array elements, and alert on the remediation event.

| Issue | Impact | Correction |
|-------|--------|-----------|
| P1 rule matches `"fromPort":(22\|3389\|5985\|5986)` as an unanchored literal | The port range is the discriminator, not the port value. `fromPort:0, toPort:65535` exposes SSH with no `22` in the event; `fromPort:1, toPort:1024` likewise; `ipProtocol:"-1"` opens every port and carries **no port fields at all**. The rule catches the actor who opened exactly one port and misses all three wide-open cases — the more damaging outcome, and the one a hurried actor sends. Being unanchored on the right, it also matches `"fromPort":2200`, `22000` and `33890` — under-matching wide ranges and over-matching high ports at the same time | Numeric range containment against a parsed integer: `fromPort <= P <= toPort` per management and database port `P`, with `-1` and any protocol outside tcp/udp/icmp/icmpv6 normalised to `0-65535`. Sigma has no arithmetic, so it enumerates the range **starts** (`0`, `1`, plus the ports themselves); the KQL and Query 1 carry the exact test |
| Port and CIDR matched as two independent regexes over the whole serialized `ipPermissions` array | One call may add several permissions. Opening 443 to `0.0.0.0/0` **and** 22 to the corporate CIDR satisfies both regexes from *different* elements and fires P1 on a routine deployment — the single most likely benign call in the estate | Descend to one `ipPermissions` element and evaluate the CIDR and the range **inside it**. Same "two substrings, different statements" defect as the IAM policy-document rules, in a different serialization |
| P2 rule reads `requestParameters.cidrIp` | A real request parameter — but only for the flattened form. The array form nests it two `items` wrappers deep and a flat path yields `null` silently. In the flattened form `ipPermissions` is *still present as an empty object*, so even testing the nested parent does not separate the shapes, and **neither rule reads `ipv6Ranges.items[].cidrIpv6` at all**, so `::/0` is uncovered end to end — the quieter path, since an IPv6 GUA is public by default and GuardDuty's flow-log findings do not cover IPv6 either | Both paths and both address families, as sibling blocks ORed — never two keys in one block, which ANDs them into a rule that can never fire. Test `ipPermissions.items`, not `ipPermissions`. Match prefix length `/0`, not the literal string: AWS canonicalizes CIDRs, so `1.2.3.4/0` becomes `0.0.0.0/0`, and real trail data contains that form |
| No `errorCode` filter on either exposure rule | A principal **without** `ec2:AuthorizeSecurityGroupIngress` hammering the API fires the identical P1 as a completed internet exposure. Both lower-priority siblings in the same set carry `NOT _exists_:errorCode`, so the idiom was known and simply not applied where it decides the disposition | Success path filtered to `errorCode: null`; denials split into a separate volume correlation at `medium`, restricted to the `UnauthorizedOperation` family so malformed and duplicate-rule errors do not inflate it |
| `RevokeSecurityGroupIngress` carried as an alerting rule at P4 | A rule removal is **remediation**, not exposure. Alerting on it beside the authorize makes the close indistinguishable from the open in the queue, and the fix buries the incident that prompted it | Drop it from the alerting path. Its correct use is as a correlation partner measuring the exposure window — first authorize to matching revoke — which is a metric, not a signal |
| `ModifySecurityGroupRules` is covered by no rule in the set | An existing rule can be widened to `0.0.0.0/0` in place with no authorize event. Every rule in the family is blind to it, and it is the natural move for an actor who can already see a management-port rule scoped to a corporate CIDR | A rule on `ModifySecurityGroupRules` whose updated CIDR is a `/0` prefix. Its CloudTrail shape is unlike the other EC2 calls — PascalCase under an XML request wrapper, doubly nested |

**Recommended detection — a `/0` ingress rule on a port range spanning a remote-management or database port.**

```yaml
# Security Group Opened to the Internet on a Remote-Management Port (T1686.001 / T1133)
#
# The original rules match the literal integer in `fromPort` — `fromPort:(22|3389|5985|5986)`.
# The port RANGE is the discriminator, not the port value. `fromPort:0, toPort:65535`
# exposes SSH without the number 22 appearing anywhere in the event, `fromPort:1,
# toPort:1024` does the same, and `ipProtocol:"-1"` opens every port on every protocol
# with no port fields at all. All three are the wide-open cases, all three are what an
# actor in a hurry actually sends, and the original rule matches none of them.
#
# The companion rule matches the CIDR at `requestParameters.cidrIp` — a real request
# parameter, but only for the FLATTENED submission form. The array form puts it at
# `requestParameters.ipPermissions.items[].ipRanges.items[].cidrIp`, two `items` wrappers
# deep, and a flat path against a nested event yields null silently. Neither rule reads
# `ipv6Ranges.items[].cidrIpv6`, so `::/0` is uncovered end to end.
#
# Both request forms are matched here as SIBLING blocks ORed in the condition. They cannot
# be two keys in one block: keys inside a block are ANDed, and the two paths never both
# resolve on one event, so ANDing them is a rule that can never fire. Note that testing for
# `ipPermissions` alone does NOT separate the forms — in the flat form it is still present,
# as an empty object. Only `ipPermissions.items` distinguishes them.
#
# `RevokeSecurityGroupIngress` is REMEDIATION — it removes an ingress rule. The source
# set alerts on it at P4. It is deliberately absent from every rule below: matching the
# close alongside the open inverts the signal and buries the exposure in its own cleanup.
#
# WHAT THESE RULES CANNOT DO. Sigma has no numeric comparison and no array-index
# correlation, so it cannot express `fromPort <= 22 <= toPort`, and it cannot require
# that the open CIDR and the spanning port sit in the SAME `ipPermissions` element. A
# call adding 443 to `0.0.0.0/0` and 22 to the corporate CIDR satisfies both blocks from
# different elements. The true range-containment test is in `kql_t1686_001.kql` and in
# Query 2 of the playbook; these rules are the substring approximation that triggers it.
# Treat a hit as the trigger for the reachability check, not as a disposition.
#
# INSIDE THE FIRST RULE, three things that are not obvious from its field names:
#   * `|endswith: '/0'` is the unrestricted-source test, and is stronger than the literal
#     string — AWS canonicalizes CIDRs, so 1.2.3.4/0 is accepted and becomes 0.0.0.0/0, and
#     real trail data carries fully-open rules in that non-canonical form. No other prefix
#     length ends in '/0': /10, /20 and /30 all end in a digit pair.
#   * the `fromPort` list is range STARTS, not port values — 0 and 1 are the wide-sweep
#     starts, the rest are the management and database ports themselves.
#   * `ipProtocol: '-1'` means all protocols and all ports "regardless of any port range you
#     specify", and those events carry no fromPort/toPort at all.
#
# FIELD-PATH CAVEAT. The nested paths below assume the ingestion pipeline flattens
# CloudTrail's `items[]` arrays into a repeated dotted field. Confirm against one real
# event in your own pipeline before deploying — a path the backend does not produce
# yields no match and no error.
title: Security group ingress opened to the internet spanning a remote-management port
id: 1531cfff-3db4-4d31-87e3-5c5736f5e6dd
name: sg_ingress_world_open_management_port
status: experimental
description: >-
  An ingress rule was created allowing an unrestricted source (prefix length /0, IPv4 or IPv6)
  on a port range reaching SSH, RDP, WinRM, VNC, SMB or a database engine — or on every
  protocol at once. The service is reachable from the whole internet the moment it lands.
references:
  - https://attack.mitre.org/techniques/T1686/001/                                              # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html                # retrieved 2026-08-27
tags:
  - attack.defense-impairment
  - attack.initial-access
  - attack.t1686.001
  - attack.t1133
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'AuthorizeSecurityGroupIngress'
  world_open_v4:
    requestParameters.ipPermissions.items.ipRanges.items.cidrIp|endswith: '/0'
  world_open_v6:
    requestParameters.ipPermissions.items.ipv6Ranges.items.cidrIpv6|endswith: '/0'
  mgmt_port_start:
    requestParameters.ipPermissions.items.fromPort: [0, 1, 22, 23, 135, 445, 1433, 1521,
      2375, 2376, 3306, 3389, 5432, 5900, 5984, 5985, 5986, 6379, 9200, 9300, 10250,
      11211, 27017, 27018]
  all_protocols:
    requestParameters.ipPermissions.items.ipProtocol: '-1'
  success:
    errorCode: null
  condition: selection and (world_open_v4 or world_open_v6) and (mgmt_port_start or all_protocols) and success
falsepositives:
  - A deliberately public listener whose range starts at 0 or 1 — a load-balancer or bastion
    group from IaC. Filter by `groupId` on a reviewed allowlist, never by principal alone.
  - A management-port rule on a group attached to nothing, or on a host with no public address
    — the grant, not the reachability. `tools/sg_reachability.sh` resolves it.
level: high
---
# THE FLAT SUBMISSION FORM, as its own rule rather than more blocks on the one above.
# The two shapes never both resolve on one event, so they cannot be keys in a single
# selection block — keys inside a block are ANDed, and ANDing paths that cannot co-occur is
# a rule that never fires. Splitting them keeps each rule readable and each condition true
# of exactly the events it describes.
#
# Beware: in this form `ipPermissions` is STILL PRESENT, as an empty object. Only the
# absence of `ipPermissions.items` distinguishes the shapes, so a rule that tests for
# `ipPermissions` alone routes flat events into the nested rule, where they match nothing.
title: Security group ingress opened to the internet on a remote-management port (flat form)
id: a6f45926-7396-4463-a091-578f7b5c002b
name: sg_ingress_world_open_management_port_flat
status: experimental
description: >-
  As the nested-form rule, but for callers that set the top-level CidrIp / FromPort /
  ToPort / IpProtocol request parameters directly instead of an IpPermissions array.
  Deploy both: which one fires depends on how the caller was written, not on intent.
references:
  - https://attack.mitre.org/techniques/T1686/001/                                              # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html # retrieved 2026-08-27
tags:
  - attack.defense-impairment
  - attack.initial-access
  - attack.t1686.001
  - attack.t1133
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'AuthorizeSecurityGroupIngress'
  world_open_flat:
    requestParameters.cidrIp|endswith: '/0'
  mgmt_port_start_flat:
    requestParameters.fromPort: [0, 1, 22, 23, 135, 445, 1433, 1521, 2375, 2376, 3306,
      3389, 5432, 5900, 5984, 5985, 5986, 6379, 9200, 9300, 10250, 11211, 27017, 27018]
  all_protocols_flat:
    requestParameters.ipProtocol: '-1'
  success:
    errorCode: null
  condition: selection and world_open_flat and (mgmt_port_start_flat or all_protocols_flat) and success
falsepositives:
  - The same public-listener and unattached-group cases as the nested-form rule.
level: high
---
# Replaces the source set's `requestParameters.cidrIp:"0.0.0.0/0"` rule. Same intent,
# three corrections: the nested path is read as well as the flat one, `::/0` is covered,
# and denied calls no longer fire. Deliberately has NO port condition — it is the
# catch-all for an unrestricted grant on a port this library has not enumerated, and it
# sits at `medium` because a public web listener is a legitimate instance of it.
title: Security group ingress opened to an unrestricted source on any port
id: b5a43615-953f-4b30-a9a6-f265e6a07b68
name: sg_ingress_world_open_any_port
status: experimental
description: >-
  A security group ingress rule was created with a source prefix length of /0 —
  the entire IPv4 or IPv6 internet — on any port. Corroborate against the port
  range and the instance's actual reachability before dispositioning.
references:
  - https://attack.mitre.org/techniques/T1133/                                                  # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html # retrieved 2026-08-27
tags:
  - attack.initial-access
  - attack.t1133
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'AuthorizeSecurityGroupIngress'
  world_open_v4:
    requestParameters.ipPermissions.items.ipRanges.items.cidrIp|endswith: '/0'
  world_open_v6:
    requestParameters.ipPermissions.items.ipv6Ranges.items.cidrIpv6|endswith: '/0'
  world_open_flat:
    requestParameters.cidrIp|endswith: '/0'
  success:
    errorCode: null
  condition: selection and (world_open_v4 or world_open_v6 or world_open_flat) and success
falsepositives:
  - Public HTTP/HTTPS listeners on ports 80 and 443. These are the dominant true-but-benign
    hit and the reason this rule is `medium` — tune by port, not by muting the rule.
level: medium
---
# The API the source set does not cover at all. `ModifySecurityGroupRules` edits an
# EXISTING rule in place, so a rule already permitting 10.0.0.0/8 on port 22 can be
# widened to 0.0.0.0/0 with no `AuthorizeSecurityGroupIngress` event ever emitted. Every
# rule keyed on the authorize event is blind to it.
#
# FIELD SHAPE — corroborated from real events and from an AWS-published CloudTrail Lake
# sample query, but NOT specified in the API reference. Unlike the authorize call, this
# one renders in CloudTrail with the XML request wrapper intact and PascalCase keys,
# doubly nested:
#   requestParameters.ModifySecurityGroupRulesRequest.SecurityGroupRule.SecurityGroupRule.CidrIpv4
# The inner `SecurityGroupRule` may also be an array when several rules are modified in
# one call. Confirm both against a real event in your own trail before deploying.
title: Existing security group rule edited to an unrestricted source
id: 21604f28-f8f7-4cb9-9aad-9b1d3098e331
name: sg_rule_edited_to_world_open
status: experimental
description: >-
  An existing security group rule was modified in place so its source became a /0
  prefix — the whole internet. This widens an already-permitted port without ever
  emitting AuthorizeSecurityGroupIngress, so rules keyed on that event do not fire.
references:
  - https://attack.mitre.org/techniques/T1686/001/                                         # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySecurityGroupRules.html # retrieved 2026-08-27
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_SecurityGroupRuleRequest.html # retrieved 2026-08-27
tags:
  - attack.defense-impairment
  - attack.initial-access
  - attack.t1686.001
  - attack.t1133
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName: 'ModifySecurityGroupRules'
  world_open_v4:
    requestParameters.ModifySecurityGroupRulesRequest.SecurityGroupRule.SecurityGroupRule.CidrIpv4|endswith: '/0'
  world_open_v6:
    requestParameters.ModifySecurityGroupRulesRequest.SecurityGroupRule.SecurityGroupRule.CidrIpv6|endswith: '/0'
  success:
    errorCode: null
  condition: selection and (world_open_v4 or world_open_v6) and success
falsepositives:
  - Console rule editing during a legitimate change window. `ModifySecurityGroupRules` is
    the API behind the console's inline rule editor, so a human widening a rule on purpose
    produces exactly this event — confirm against the change record, not against volume.
level: high
---
title: Security group ingress authorization denied
id: b924d3fb-f776-4b3b-b297-94ecdf85e2f4
name: sg_ingress_authorize_denied
status: experimental
description: Base rule — volume component only, not for direct alerting.
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html   # retrieved 2026-08-27
tags:
  - attack.discovery
  - attack.t1686.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'ec2.amazonaws.com'
    eventName:
      - 'AuthorizeSecurityGroupIngress'
      - 'ModifySecurityGroupRules'
      - 'CreateSecurityGroup'
  # EC2 prefixes its CloudTrail error codes with `Client.` — the unprefixed form is the
  # SDK's error code and matches nothing in a trail. `contains` is prefix-tolerant and
  # catches both `Client.UnauthorizedOperation` and a bare `UnauthorizedOperation`.
  denied:
    errorCode|contains: 'UnauthorizedOperation'
  condition: selection and denied
level: low
---
# Kept strictly separate from the success-path rules. The source set has no `errorCode`
# filter on either exposure rule, so a principal WITHOUT ec2:AuthorizeSecurityGroupIngress
# hammering the API fires the identical P1 as a completed internet exposure. Its two
# lower-priority siblings both carry `NOT _exists_:errorCode`, so the idiom was known and
# simply not applied to the rules where it decides the disposition.
#
# Threshold basis: derived from operator behaviour, not from an observed baseline. Opening
# one port is one call; a human who gets UnauthorizedOperation reads the message and stops
# or asks for the permission. An actor sweeping which security groups it can write walks
# groups, and a misconfigured IaC apply retries the same call on a fixed interval — the
# per-principal grouping and ten-minute window separate those from each other. Four or
# more denials in ten minutes sits above ordinary human retry. Baseline against your own
# account before deploying: a starting point, not a measurement.
title: Security group write calls denied repeatedly for one principal
id: cf8cec61-1e31-411c-97d6-7c086ea1f0ea
status: experimental
description: >-
  One principal was denied four or more security group write calls within ten minutes —
  an actor establishing which security groups its credentials can modify before it opens
  one. Reconnaissance, not exposure; it must not share an alert with a completed grant.
references:
  - https://attack.mitre.org/techniques/T1686/001/    # retrieved 2026-08-27
tags:
  - attack.discovery
  - attack.t1686.001
correlation:
  type: event_count
  rules:
    - sg_ingress_authorize_denied
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gt: 3
level: medium
```

Reproduced byte-for-byte from the first rule document of
`detections/sigma_t1686_001.yml` (its leading comment block is not repeated — §2 says
the same in prose). Five further documents ship there: **the same rule for the flat
submission form** (`high`, not optional — which of the two fires depends on how the
caller was written), the unrestricted-source catch-all (`medium`), the
`ModifySecurityGroupRules` in-place widening (`high`), the omitted-`requestParameters`
companion (`medium`), and the denied security-group-write base rule (`low`) with its
volume correlation (`medium`). **Deploy the file, not this excerpt.**

**What this rule structurally cannot do.** Two questions decide whether an ingress rule is this
technique, and neither is a substring question. *Does the port range contain the management port*
is arithmetic, which Sigma cannot express — it approximates it by enumerating range **starts**,
leaving a real gap: `fromPort: 20, toPort: 30` reaches SSH and matches no enumerated start. *Do
the open CIDR and the spanning range sit in the same `ipPermissions` element* needs array-index
correlation, which Sigma has none of. Both are answered exactly in `kql_t1686_001.kql` and by the
shared range test. **Treat a Sigma hit as the trigger for that test and the reachability check,
not as a disposition.** Full reasoning: `detections/detection_note_t1686_001.md`.

---

### Key Investigation Queries

> **Security group events are regional** — run these in the region the group lives in, and repeat per region; there is no global vantage point as there is for IAM. Extraction uses `--output json | jq '.Events[].CloudTrailEvent | fromjson'`. **`lookup-events` returns ≤50 events per page** — paginate on `NextToken` or use your log platform for busy windows.

#### Query 1 — Reconstruct: who opened what range, to which source, on which group

```bash
REGION="us-east-1"; WINDOW="24 hours ago"; KIT="<path-to-playbook-authoring-kit>"

for EV in AuthorizeSecurityGroupIngress ModifySecurityGroupRules; do
  aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=EventName,AttributeValue="$EV" \
    --start-time "$(date -u -d "$WINDOW" +%Y-%m-%dT%H:%M:%SZ)" \
    --region "$REGION" --output json 2>/dev/null
done | \
  jq -c '.Events[].CloudTrailEvent | fromjson | select(.eventSource == "ec2.amazonaws.com")' | \
  python3 "$KIT/tools/sg_open_rule_test.py" | jq -s -c 'sort_by(.time)[]'
```

`tools/sg_open_rule_test.py` normalises all three request shapes and runs the range test, emitting
**one row per source range per permission** — so the CIDR and the range on any row belong together.
That pairing is the point: a deployment opening 443 to the world and 22 to the office yields two
rows, one `world_open` with empty `spans` and one with `spans: [22]` that is not `world_open`,
neither an incident. The source rule fires on it.

**A row with `world_open: true`, a non-empty `spans` and `error: "SUCCESS"` is the
technique.** Rows whose `error` is `Client.UnauthorizedOperation` are the probing path —
count them per `caller_arn`, never score them as exposures; other `Client.` codes are
malformed or duplicate requests, not denials. Record `group_id`, `caller_arn`, `access_key`,
`region`, the earliest `time` and `spans`. `rule_ids` is empty for failed calls and for
`ModifySecurityGroupRules` — hence Query 2 is the containment authority.

#### Query 2 — Sweep: every live ingress rule whose range spans a management port on a `/0` source

CloudTrail says what changed in the window; this says what is open **right now**,
including exposure older than retention, and emits the `sgr-` rule IDs that make
containment surgical. `describe-security-groups` returns `IpPermissions` and **no rule
IDs**; the `-rules` call does.

```bash
REGION="us-east-1"; KIT="<path-to-playbook-authoring-kit>"
EVIDENCE="/tmp/ir-sg-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$EVIDENCE"

aws ec2 describe-security-group-rules --region "$REGION" --output json \
  > "$EVIDENCE/sg-rules-live.json"

python3 "$KIT/tools/sg_open_rule_test.py" --live < "$EVIDENCE/sg-rules-live.json" \
  | tee "$EVIDENCE/open-mgmt-rules.jsonl" \
  | jq -r '"[!] \(.group_id) \(.rule_id) \(.proto) \(.port_range) \(.cidr) spans=\(.spans|join(","))"'
```

Every `[!]` line is a rule open to the whole internet on a range reaching a management or
database service, right now; the `sgr-` id is the field after the group id, and is what
Containment Step 1 revokes. Reconcile against the §1 baseline: here and not there is this
incident or an older one, in both is accepted risk for §6. Anything Query 1 does not show
predates CloudTrail retention — a finding in itself, and unattributable.

#### Query 3 — Reachability: is anything actually exposed by this group

The grant is not the exposure. A security group has effect only on the resources it is
**associated with**, and four conditions must all hold before internet traffic arrives: the
group is attached to an ENI; that ENI has a public IPv4/EIP or an IPv6 GUA; the subnet routes
`0.0.0.0/0` to an internet gateway; and the subnet's NACL permits the port inbound *and* the
ephemeral range (1024-65535) outbound, NACLs being stateless. Two of those have an **inverted
default** that turns empty output into a confident wrong answer — an implicit main-route-table
association, and an implicit default NACL that allows everything — which is why this is a
script rather than four commands by hand.

```bash
KIT="<path-to-playbook-authoring-kit>"
bash "$KIT/tools/sg_reachability.sh" "<group-id-from-Query-1>" us-east-1
```

`REACHABLE via igw-…` means the port range from Query 1 was open to the entire internet from the
moment the rule landed — **P0, go to Containment**. `no-public-address` or
`no-internet-gateway-route` means misconfiguration, not live exposure: still remove the rule, but
the incident is Medium. Where it must be authoritative, `create-network-insights-path
--source <igw-id> --destination <instance-id> --destination-port <port> --protocol TCP` then
`start-network-insights-analysis` settles it — configuration-modelled, no packets sent,
IPv4-only, billed per analysis. The script emits `eni=` and `instance=` for Query 5 and Step 3.

#### Query 4 — Session reconstruction: what else the principal did

```bash
REGION="us-east-1"; ACCESS_KEY_ID="<access-key-from-Query-1>"
OPEN_TIME="<time-from-Query-1>"          # ISO8601, the moment the rule was created

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue="$ACCESS_KEY_ID" \
  --start-time "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --region "$REGION" --output json | \
  jq -r --arg t "$OPEN_TIME" '.Events[].CloudTrailEvent | fromjson |
    {time: .eventTime, event: .eventName, source: .eventSource,
     phase: (if .eventTime > $t then "AFTER-OPEN" else "before" end),
     error: (.errorCode // "SUCCESS"), ip: .sourceIPAddress}' | \
  jq -s -c 'sort_by(.time)[]'
```

The reconnaissance *before* the rule is as informative as what follows: a `DescribeSecurityGroups`
/ `DescribeInstances` / `DescribeNetworkInterfaces` burst is an actor picking a target with a
public address, which separates this from a careless engineer. `AFTER-OPEN` rows that matter:
further security-group writes, `AuthorizeSecurityGroupEgress`, `CreateNetworkAclEntry` /
`ReplaceNetworkAclEntry` (removing the layer that might still have blocked it), `AssociateAddress`
(a public IP, so the rule *becomes* reachable), `RunInstances`, and any IAM `Create*` / `Put*`.

> If the principal is an **instance-profile role**, its session name is the **instance ID**, not
> the role name. Any follow-up `lookup-events` for that role must use
> `AttributeKey=Username,AttributeValue=<instance-id>` and post-filter on
> `.userIdentity.sessionContext.sessionIssuer.userName` — keyed on the role name it returns zero
> events and reads as "the role did nothing".

#### Query 5 — Was it used: connections accepted on the exposed port

The "was it used" pivot. Security-group changes are management events and complete, but
**connections are in no trail at any configuration** — a `lookup-events` query here returns zero
forever and that zero means nothing. VPC Flow Logs are the only record.

```bash
REGION="us-east-1"; FLOW_LOG_GROUP="<vpc-flow-log-group-name>"
ENI="<eni-from-Query-3>"; PORT="<exposed-port-from-Query-1>"   # a value in Query 1's `spans`
START_MS=$(( $(date -u -d "<time-from-Query-1>" +%s) * 1000 ))

aws logs filter-log-events --region "$REGION" \
  --log-group-name "$FLOW_LOG_GROUP" --start-time "$START_MS" \
  --filter-pattern "$ENI" --output json 2>/dev/null | \
  jq -r '.events[].message' | \
  awk -v p="$PORT" '$7 == p && $13 == "ACCEPT" { print $4 }' | \
  sort | uniq -c | sort -rn | head -20
```

Default v2 fields: 4 `srcaddr`, 7 `dstport`, **13 `action`**, 14 `log-status`. Every line is
an internet source that **completed a connection**, with its count. One or two addresses
hitting once is scanning; one source with hundreds of ACCEPTs is a brute-force run, and the
host is compromised rather than merely exposed. An empty result is weak evidence: delivery
lags ~5 minutes, `SKIPDATA` means the capture dropped packets, and if flow logs go to **S3**
this command does not apply — query them in Athena. Corroborate with GuardDuty
`UnauthorizedAccess:EC2/SSHBruteForce`, `.../RDPBruteForce` and `Impact:EC2/WinRMBruteForce`,
which derive from flow logs too and therefore **do not see IPv6**.

---

## 3. Containment

### Immediate Actions (first 15 minutes)

Revoking the ingress rule takes effect on new connections almost immediately, so closing
the hole is both the first step and the cheap one. What it does **not** do is terminate
sessions already established through it, or undo anything done on the host — hence the
ordering: close the rule, then treat every host behind it as accessed.

> Run every command under the **break-glass responder credentials** from §1 — not under any
> principal being contained, and not under the principal that opened the rule.

> Revoking **ingress** does not affect SSM Session Manager, which depends on the instance's
> *outbound* 443. Do not substitute a zero-egress "isolation" security group: that severs the
> SSM agent, and every later `start-session` and `send-command` here hangs. If you must
> isolate at the network layer, keep 443 outbound open.

#### Step 1 — Capture the rule, then revoke it by rule ID

```bash
REGION="us-east-1"; SG_ID="<group-id-from-Query-1>"
EVIDENCE="/tmp/ir-sg-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$EVIDENCE"
RULE_ID="<security-group-rule-id-from-Query-2>"   # the sgr-... after the group id

# Capture before revoking — describe-security-group-rules is the only call that returns the
# rule as an addressable object, and after the revoke it is gone.
if aws ec2 describe-security-group-rules --region "$REGION" \
     --security-group-rule-ids "$RULE_ID" --output json \
     > "$EVIDENCE/rule-$RULE_ID.json" 2>/dev/null; then
  echo "[OK] Captured $RULE_ID to $EVIDENCE/rule-$RULE_ID.json"
  aws ec2 revoke-security-group-ingress --region "$REGION" \
    --group-id "$SG_ID" --security-group-rule-ids "$RULE_ID" && \
    echo "[OK] Revoked $RULE_ID from $SG_ID — the port is no longer open to the internet"
else
  rm -f "$EVIDENCE/rule-$RULE_ID.json"
  echo "[!] $RULE_ID not found — already revoked, or in another region. Re-run Query 2 in every region before concluding it is closed"
fi
```

> Revoke by **rule ID**, not by re-specifying protocol, port and CIDR — re-specifying matches
> whatever rule happens to fit, and can remove a different one, or nothing at all while still
> returning success.

#### Step 2 — Close every other internet-open management rule the sweep found

```bash
REGION="us-east-1"
OPEN_RULES_FILE="$EVIDENCE/open-mgmt-rules.jsonl"   # written by Query 2

[ -s "$OPEN_RULES_FILE" ] || echo "[i] $OPEN_RULES_FILE empty or missing — re-run Query 2"
jq -r '"\(.group_id) \(.rule_id) \(.port_range) \(.cidr)"' "$OPEN_RULES_FILE" 2>/dev/null |
while read -r G R REST; do
  { [ -z "$G" ] || [ -z "$R" ]; } && continue
  aws ec2 describe-security-group-rules --region "$REGION" --security-group-rule-ids "$R" \
    --output json > "$EVIDENCE/rule-$R.json" 2>/dev/null || continue
  aws ec2 revoke-security-group-ingress --region "$REGION" --group-id "$G" \
    --security-group-rule-ids "$R" >/dev/null 2>&1 \
    && echo "[OK] Revoked $R from $G  ($REST)" \
    || echo "[FAIL] Could not revoke $R from $G — revoke by hand"
done
```

> Confirm each group's purpose first. Query 2 emits only rules whose range spans a management
> or database port, so a plain `/0` on 443 is not in the file — but a group fronting a public
> service that *also* carries a wide range will be, and revoking it is an outage.

#### Step 3 — Treat every host behind the group as accessed

Closing the rule ends the exposure. It does not evict what came through it.

```bash
REGION="us-east-1"; INSTANCE_ID="<instance-id-from-Query-3>"

# Snapshot the root volume for forensics BEFORE anything on the host is changed.
for VOL in $(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
      --query 'Reservations[].Instances[].BlockDeviceMappings[].Ebs.VolumeId' --output text 2>/dev/null); do
  aws ec2 create-snapshot --region "$REGION" --volume-id "$VOL" --query 'SnapshotId' --output text \
    --description "IR snapshot $INSTANCE_ID $(date -u +%Y%m%dT%H%M%SZ)" && echo "[OK] Snapshotted $VOL"
done

# The instance-profile role's credentials were readable from IMDS by anything with a shell.
ROLE=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
        --query 'Reservations[].Instances[].IamInstanceProfile.Arn' --output text 2>/dev/null \
        | awk -F'/' '{print $NF}')
{ [ -n "$ROLE" ] && [ "$ROLE" != "None" ]; } \
  && { echo "[!] $INSTANCE_ID carries instance profile $ROLE — its credentials are exposed"; \
       aws iam list-attached-role-policies --role-name "$ROLE" --output table 2>/dev/null; } \
  || echo "[i] $INSTANCE_ID has no instance profile — nothing reachable from IMDS"
```

#### Step 4 — Contain the principal that opened the rule

```bash
SUSPECT_ARN="<caller-arn-from-Query-1>"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
REVOKE_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$NOW"'"}}}]}'
DENY_DOC='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["ec2:AuthorizeSecurityGroupIngress","ec2:AuthorizeSecurityGroupEgress","ec2:ModifySecurityGroupRules","ec2:CreateSecurityGroup","ec2:CreateNetworkAclEntry","ec2:ReplaceNetworkAclEntry","ec2:AssociateAddress"],"Resource":"*"}]}'

if echo "$SUSPECT_ARN" | grep -q ":user/"; then
  U=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $NF}')        # user ARN: name = LAST segment
  for K in $(aws iam list-access-keys --user-name "$U" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    aws iam update-access-key --user-name "$U" --access-key-id "$K" --status Inactive \
      && echo "[OK] Disabled key $K for $U"
  done
  aws iam put-user-policy --user-name "$U" --policy-name "EmergencyDenySGWrite" \
    --policy-document "$DENY_DOC" && echo "[OK] Denied further network writes by user $U"
elif echo "$SUSPECT_ARN" | grep -q ":assumed-role/"; then
  R=$(echo "$SUSPECT_ARN" | awk -F'/' '{print $2}')         # role ARN: name = 2nd segment
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyRevokeSessions" \
    --policy-document "$REVOKE_DOC" && echo "[OK] Revoked sessions for role $R"
  aws iam put-role-policy --role-name "$R" --policy-name "EmergencyDenySGWrite" \
    --policy-document "$DENY_DOC" && echo "[OK] Denied further network writes by role $R"
else
  echo "[i] $SUSPECT_ARN is neither an IAM user nor an assumed-role — root/federated: contain manually"
fi
```

> `aws:TokenIssueTime` denies only tokens issued **before** the cutoff — a credential re-fetched
> from IMDS afterwards is not denied, so this kills currently-leaked session tokens and does not
> gate the role. If the principal is an instance-profile role on the exposed host itself, Step 3's
> snapshot must precede this and the role must be replaced, not just revoked.

---

## 4. Eradication

### Remove Attacker Access

#### Confirm no `/0` ingress rule survives, in every region

Security groups are regional and Query 2 sweeps one. An actor who can write security
groups can also `RunInstances`, and an unmonitored region is where that goes.

```bash
KIT="<path-to-playbook-authoring-kit>"
for R in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws ec2 describe-security-group-rules --region "$R" --output json 2>/dev/null \
    | python3 "$KIT/tools/sg_open_rule_test.py" --live 2>/dev/null \
    | jq -r --arg r "$R" '"[!] \($r) \(.group_id) \(.rule_id) \(.port_range) \(.cidr)"'
done
echo "[OK] All-region sweep complete — every [!] needs a documented owner"
```

#### Remove the rest of what the principal changed

From Query 4's `AFTER-OPEN` rows, in order of how long each outlives the rule:

- **Egress rules** added in the window — the outbound path; revoking ingress does nothing to it
- **Network ACL entries** — `CreateNetworkAclEntry` / `ReplaceNetworkAclEntry` removing the
  subnet-level layer that might still have blocked the port; and **Elastic IP associations**,
  where `AssociateAddress` turns an "unreachable" Query 3 verdict into a reachable one
- **New security groups** — `CreateSecurityGroup` plus `ModifyInstanceAttribute` or
  `ModifyNetworkInterfaceAttribute` attaches a fresh group rather than editing a watched one;
  likewise any instance launched in the window, and any IAM change — each its own playbook

#### Right-size the permission that made this possible

```bash
# Which policy grants ec2:AuthorizeSecurityGroupIngress? Check BOTH the attached (managed)
# and inline lists — list-attached-* alone returns managed policies only.
aws iam list-attached-role-policies --role-name "<suspect-role-name>" --output table 2>/dev/null
aws iam list-role-policies          --role-name "<suspect-role-name>" --output table 2>/dev/null
aws iam list-attached-user-policies --user-name "<suspect-user-name>" --output table 2>/dev/null
aws iam list-user-policies          --user-name "<suspect-user-name>" --output table 2>/dev/null
```

**There is no IAM condition key for the CIDR, the port or the protocol of a security group rule.**
The authorization context for `ec2:AuthorizeSecurityGroupIngress` carries only `aws:ResourceTag`,
`ec2:ResourceTag`, `ec2:SecurityGroupID` and `ec2:Vpc`, so no policy can permit the call on a
narrow CIDR while denying it on `0.0.0.0/0`. IAM scopes *who* and *which VPC*, never *what*; the
control that caps the outcome is VPC Block Public Access (§6).

#### Remove emergency policies once clean

```bash
for RN in "<suspect-role-name>" "<instance-profile-role-name>"; do
  aws iam delete-role-policy --role-name "$RN" --policy-name "EmergencyRevokeSessions" 2>/dev/null
  aws iam delete-role-policy --role-name "$RN" --policy-name "EmergencyDenySGWrite"    2>/dev/null
done
# Step 4 uses put-user-policy when the principal was an IAM USER — delete-role-policy does
# not cover that path.
aws iam delete-user-policy --user-name "<suspect-user-name>" --policy-name "EmergencyDenySGWrite" 2>/dev/null
# D-0: assert, do not announce. delete-*-policy exits 0 whether or not anything was
# there, so re-list and confirm absence; a listing failure is INCONCLUSIVE, never [OK].
LEFT=0; UNK=0
for RN in "<grantor-role-name>" "<grantee-role-name>"; do
  L=$(aws iam list-role-policies --role-name "$RN" --query 'PolicyNames[]' --output text 2>/dev/null)
  if [ -z "$L" ] && ! aws iam get-role --role-name "$RN" >/dev/null 2>&1; then UNK=$((UNK+1)); continue; fi
  printf '%s' "$L" | tr '\t' '\n' | grep -qE '^Emergency' && { echo "[FAIL] $RN still carries an Emergency* policy"; LEFT=$((LEFT+1)); }
done
U=$(aws iam list-user-policies --user-name "<grantor-user-name>" --query 'PolicyNames[]' --output text 2>/dev/null)
printf '%s' "$U" | tr '\t' '\n' | grep -qE '^Emergency' && { echo "[FAIL] grantor user still carries an Emergency* policy"; LEFT=$((LEFT+1)); }
[ "$UNK" -gt 0 ] && echo "[!] $UNK principal(s) could not be listed — INCONCLUSIVE, not clean"
{ [ "$LEFT" -eq 0 ] && [ "$UNK" -eq 0 ]; } && echo "[OK] No Emergency* policy remains on any contained principal"
```

---

## 5. Recovery

### Restore Clean State

#### Verify the rule is gone and no management port remains open

```bash
REGION="us-east-1"; KIT="<path-to-playbook-authoring-kit>"
RULE_ID="<security-group-rule-id-from-Query-2>"

aws ec2 describe-security-group-rules --region "$REGION" --security-group-rule-ids "$RULE_ID" \
  >/dev/null 2>&1 && echo "[FAIL] $RULE_ID still exists in $REGION" \
                  || echo "[OK] $RULE_ID no longer exists in $REGION"

REMAINING=$(aws ec2 describe-security-group-rules --region "$REGION" --output json \
  | python3 "$KIT/tools/sg_open_rule_test.py" --live 2>/dev/null | wc -l | tr -d ' ')

[ "$REMAINING" -eq 0 ] && echo "[OK] No live ingress rule in $REGION spans a management port on a /0 source" \
                       || echo "[FAIL] $REMAINING such rule(s) remain — re-run Query 2 and Containment Step 2"
```

#### Verify nothing connected on the exposed port after containment

```bash
# Query 5, re-bounded to the containment timestamp and counted rather than listed. Run this at
# least ten minutes after the revoke — delivery lags. A zero proves nothing REACHED the port,
# not that nothing already on the host is still there.
REGION="us-east-1"; FLOW_LOG_GROUP="<vpc-flow-log-group-name>"
ENI="<eni-from-Query-3>"; PORT="<exposed-port-from-Query-1>"; CONTAINED_MS=$(( $(date -u -d "<containment-timestamp>" +%s) * 1000 ))

ACCEPTED=$(aws logs filter-log-events --region "$REGION" \
  --log-group-name "$FLOW_LOG_GROUP" --start-time "$CONTAINED_MS" \
  --filter-pattern "$ENI" --output json 2>/dev/null | jq -r '.events[].message' | \
  awk -v p="$PORT" '$7 == p && $13 == "ACCEPT" { c++ } END { print c+0 }')

[ "$ACCEPTED" -eq 0 ] && echo "[OK] No accepted flow to port $PORT on $ENI since containment" \
                      || echo "[FAIL] $ACCEPTED accepted flow(s) since containment — the rule is not actually closed, or another group still permits it"
```

#### Confirm the corrected detection fires

Executable rather than described: six event shapes the detection **must** fire on and
four near-misses it **must not**, asserted against the same code the queries run.
Non-zero exit on any failure.

```bash
KIT="<path-to-playbook-authoring-kit>"
python3 "$KIT/tools/sg_open_rule_test.py" --self-test
```

The script names each case as it asserts it. The one to understand is the last must-not-fire case:
**one call adding 443 to `0.0.0.0/0` and 22 to `10.0.0.0/8`**, both conditions present but in
*different* `ipPermissions` elements. The source rule fires on it; this must not, and Sigma cannot
make the distinction — which is why a Sigma hit is a trigger, not a verdict.

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A principal could open a security group to the entire internet on a management port | `ec2:AuthorizeSecurityGroupIngress` held outside the IaC pipeline, with no VPC Block Public Access above it to cap the outcome |
| The exposure was not detected, or was detected late | The deployed rules matched the port **value** rather than the port **range**, so every wide-open form passed; the CIDR was read at a path resolving for only one of the two request shapes; `::/0` was not read at all |
| A denied probe and a completed exposure were indistinguishable, and the remediation event was itself an alert | Neither exposure rule filtered `errorCode`, though two lower-priority rules in the same set did; and `RevokeSecurityGroupIngress` alerted at P4, so closing the hole generated queue traffic resembling the incident |
| Nobody could say whether anything actually connected | VPC Flow Logs absent, or delivered somewhere no responder could query in the first hour, leaving "was it used" unanswerable during the incident |
| A shell on the host was worth more than the host | Least privilege not applied to the instance profile, so IMDS credentials reached far beyond the instance |

### Recommended Guardrails

**VPC Block Public Access — the only preventative control that survives the grant**

```json
// NOT an IAM policy — a Region-level VPC setting, via ec2:ModifyVpcBlockPublicAccessOptions.
//   block-bidirectional — all traffic to and from internet gateways is blocked
//   block-ingress       — internet traffic INTO the Region's VPCs; outbound and its return keeps working
// It sits ABOVE the security group, the NACL and the route table, so it holds even when someone
// writes 0.0.0.0/0 on port 22. Flow Logs v8 record reject-reason = BPA for what it drops.
```

**Scope who may write security groups, and in which VPC**

```json
// SCP fragment (wrap in a full {"Version":"2012-10-17","Statement":[ ... ]} document):
{
  "Effect": "Deny",
  "Action": ["ec2:AuthorizeSecurityGroupIngress", "ec2:ModifySecurityGroupRules", "ec2:CreateSecurityGroup"],
  "Resource": "*",
  "Condition": { "ArnNotLike": { "aws:PrincipalArn": ["arn:aws:iam::*:role/iac-deploy", "arn:aws:iam::*:role/BreakGlassAdmin"] } }
}
```

> A **scope** control, not a content control, and that distinction is the whole lesson here: with
> **no IAM condition key for the CIDR, port or protocol**, a policy that appears to deny
> `0.0.0.0/0` on port 22 is a no-op that reads as protection. A `*` in a condition value also needs
> a `*Like` operator — `ArnNotLike`, never `StringNotEquals`, which does not expand `*` and in a
> `Deny` denies everything.

**Structural controls**
- **Block Public Access is the control that holds when the principal is legitimate** — every
  allowlist above exempts the IaC pipeline, and pipeline credentials are what an actor who has
  them will use. Pair it with **security groups managed through reviewed IaC** and drift
  detection, so the allowlist has one entry and every out-of-band call is signal
- **Reach management planes through SSM Session Manager, not an inbound port.** An estate with
  no SSH or RDP ingress rule anywhere has nothing legitimate to tune around, which is what
  makes the rule cheap to run
- **Least-privilege instance profiles** — the blast-radius reducer for when someone gets a shell
- **AWS Config**, detective, all three evaluating the group in isolation without knowing whether
  it is attached: `restricted-ssh` (`INCOMING_SSH_DISABLED`), `restricted-common-ports`
  (`RESTRICTED_INCOMING_TRAFFIC`, whose default blocked ports are 20, 21, 3389, 3306 and 4333 —
  **port 22 is not among them** and must be added), and `vpc-sg-open-only-to-authorized-ports`
  (`VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS`)

**Detection improvements**
- Deploy the range-containment rules; never a literal `fromPort` match. Match the CIDR on
  **prefix length `/0`**, not the literal `0.0.0.0/0` — AWS canonicalizes CIDRs and real trail
  data carries fully-open rules in non-canonical form
- Cover both request shapes and both address families, and `ModifySecurityGroupRules`, which
  reaches the same outcome with no authorize event
- Split denied from successful, and **remove `RevokeSecurityGroupIngress` from the alerting
  path** — keep it only as the correlation partner measuring the exposure window. Enrich the
  alert with the Query 3 reachability verdict, so the analyst gets a P0 or a P2 rather than
  four API calls

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1686.001 — Disable or Modify System Firewall: Cloud Firewall; T1133 — External Remote Services |
| MITRE tactic | Defense Impairment (TA0112), Initial Access (TA0001) |
| Primary API | `ec2:AuthorizeSecurityGroupIngress`; `ec2:ModifySecurityGroupRules` for in-place widening |
| Event source | `ec2.amazonaws.com` — **management** events, **regional**; there is no security-group data-event type |
| Key discriminator | Source prefix length `/0` **and** `fromPort <= P <= toPort` for a management or database port `P` — or `ipProtocol` `-1` — read from the **same** `ipPermissions` element. The port **range**, never the port value |
| Ground truth / pivot | `describe-security-group-rules` for what is open now, with per-rule `sgr-` IDs. "Was it used": **VPC Flow Logs** ACCEPT on the port — connections are in no trail at any configuration, so a `lookup-events` zero is meaningless |
| Field-shape traps | Two request shapes: `ipPermissions.items[].ipRanges.items[].cidrIp` (two `items` wrappers) or flat `requestParameters.cidrIp`. In the flat form `ipPermissions` is present as an **empty object** — test `ipPermissions.items`. An unused range family is likewise an empty object with no `items`. `responseElements` uses `_return` (underscore) and `cidrIpv4`/`cidrIpv6`, and is `null` on failure. `ModifySecurityGroupRules` renders PascalCase under an XML request wrapper |
| Blast radius | Every listener in the port range on every resource associated with the group, reachable from every host on the internet — and, if a shell follows, the instance profile's role and everything it can reach |
| Error strings | `Client.`-prefixed, unlike IAM. `Client.UnauthorizedOperation` is the denial. **Not** denials: `Client.InvalidPermission.Duplicate`, `Client.InvalidPermission.Malformed`, `Client.RulesPerSecurityGroupLimitExceeded`, `Client.InvalidGroup.NotFound`, `Client.InvalidGroupId.Malformed`, `Client.InvalidParameterValue`, `Client.MissingParameter` |
| Reachability requirement | Grant ≠ exposure. Needs an attached ENI, a public address, an internet-gateway route and a permissive NACL. A subnet with no explicit route-table association uses the VPC **main** table; one with no explicit NACL association uses the **default** NACL, which **allows everything** |

**MITRE mapping note:** the source set tags the remote-management alert `T1686.001` (*Impair
Defenses: Disable or Modify Cloud Firewall*, Defense Impairment) and the bare `0.0.0.0/0` alert
`T1133` (*External Remote Services*, Initial Access). Both are right, and they describe
different halves of the same event: modifying the cloud firewall is T1686.001, what it enables is
T1133, and this directory carries both. The set's other two mappings are not defensible. `Ingress
Rule Was Added` is tagged `T1078` (*Valid Accounts*) — authenticating with legitimate credentials,
not adding a firewall rule. Mapping-precision notes on the two low-priority rules, not operational defects.

### Residual Risk

**The rule is closed; whatever came through it is not.** Revoking it stops new connections and
does nothing about a session already established, a key already added to `authorized_keys`, a
task already installed, or an instance-profile credential already read from IMDS and now in use
elsewhere. Query 5 says whether anything connected, not what it did once it had. Every host
behind the group during the window is presumed accessed until its own audit log says otherwise,
and Step 3's snapshot is the only evidence of its pre-remediation state. **The window may also
be longer than the CloudTrail event suggests:** Query 2 routinely finds `/0` management rules
with no authorize event in retention — real, current exposure whose start and author are
unknowable, bounded only by flow logs, which have their own retention and `SKIPDATA` gaps.

**Anything the instance-profile role could reach stays reached.** If a shell was obtained, every
secret those credentials could retrieve — Secrets Manager values, SSM `SecureString` parameters,
S3 objects, database credentials — is disclosed and must be rotated. Revoking the role's sessions
denies tokens issued before the cutoff and does not stop a fresh fetch from a still-compromised
host, so remediate the host before trusting the role again.

**Detection coverage stays partial by construction.** The Sigma rules approximate a numeric range
test by enumerating range starts, so `20-30` reaching SSH passes them. The KQL and the shared range
test close that gap but run on a schedule, not on every event. Until the range test runs
continuously in the platform, the residual gap is the set of ranges nobody thought to enumerate —
the same failure mode as the rule this playbook replaces, one level further in.
