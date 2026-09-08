# Ground truth — Amazon GuardDuty findings

Audited 2026-08-30 against the AWS GuardDuty User Guide (*Severity levels*, *Finding aggregation*).
Every playbook under `techniques/guardduty.*` is written from this file.

---

## 1. Severity bands — quoted, because the source rules encode them and get them right

> The value of the severity can fall anywhere within the 1.0 to 10.0 range, with higher values
> indicating greater security risk... GuardDuty breaks down this range into *Critical*, *High*,
> *Medium*, and *Low* severity levels.

| Level | Value range | AWS's description, abbreviated |
|---|---|---|
| **Critical** | **9.0 – 10.0** | *"an attack sequence may be in progress or had recently happened"* |
| **High** | **7.0 – 8.9** | *"the resource in question... is compromised and is actively being used for unauthorized purposes"* |
| **Medium** | **4.0 – 6.9** | *"suspicious activity that deviates from normally observed behavior"* |
| **Low** | **1.0 – 3.9** | *"attempted suspicious activity that did not compromise your environment, for example, a port scan or a failed intrusion attempt"* |

The source pack's four severity rules map these ranges exactly. **This is correct and is recorded
as such** — the bands are easy to get wrong and a reviewer should not "fix" them.

Note what AWS says a Low finding *is*: an attempt that did not succeed. That is why the source
pack's 24-hour window on the Low rule is defensible where a 5-minute window would not be.

## 2. Findings are aggregated, and the old details are DESTROYED

> If GuardDuty detects a new activity related to the same security issue, then instead of creating
> a new finding, GuardDuty will update the original finding with the latest details.

> ...multiple access attempts against your instance will be aggregated to the same finding ID,
> increasing the **Count** number in the finding's details.

And the sentence that changes how a finding must be read:

> When a finding is aggregated, it is updated with information from the latest occurrence of that
> activity. This means that... if your instance is the target of a brute force attempt from a new
> actor, **the finding details will be updated to reflect the remote IP of the most recent source
> and older information will be replaced.** Complete information about individual activity attempts
> will still be available in your CloudTrail logs or VPC Flow Logs.

**Consequences, and they are large:**

1. **A finding is a summary index, not evidence.** A brute-force campaign from fifty addresses
   produces **one** finding naming **one** address — the most recent. A blocklist built from
   GuardDuty findings contains one address out of fifty and the responder believes it is complete.
2. **Counting findings under-counts activity by an unbounded factor.** `service.count` carries the
   number of aggregated occurrences; the finding count does not.
3. **AWS names the evidence explicitly**: CloudTrail and VPC Flow Logs. Every GuardDuty playbook
   here treats the finding as the *pointer* and those sources as the record.
4. **A new resource gets a new finding.** Aggregation is per security issue per resource, so the
   same activity against a second instance produces a second finding ID.

Attack-sequence findings aggregate only *"when GuardDuty identifies the similar signals in the same
sequence"*, so those behave differently again.

## 3. `userFeedback` is not a suppression mechanism

`service.userFeedback` records whether a user marked a finding **useful or not useful**. It is
feedback on GuardDuty's accuracy, not a decision to stop alerting.

The suppression mechanism is a **suppression rule** — a filter with auto-archive — and its effect
appears as `service.archived: true`. Archived findings are not re-notified.

**A rule excluding findings that carry `userFeedback` therefore silences a finding the moment
anyone marks it — including marking it USEFUL, which means confirming it is a true positive.** That
is the inversion the shipped rules remove.

## 4. Finding shape as delivered to EventBridge

The EventBridge event wraps the finding under `detail`. Fields that matter:

`detail.id` (stable across aggregation updates) · `detail.severity` (numeric, 1.0–10.0) ·
`detail.type` (the finding type string, e.g. `UnauthorizedAccess:EC2/SSHBruteForce`) ·
`detail.accountId` · `detail.region` · `detail.createdAt` · `detail.updatedAt` ·
`detail.service.count` · `detail.service.archived` · `detail.service.userFeedback` ·
`detail.service.serviceName` · `detail.service.action` (the action object, whose shape depends on
`actionType`) · `detail.service.resourceRole` (`ACTOR` or `TARGET`) · `detail.resource` (the
affected resource, whose shape depends on `resourceType`).

**`detail.service.resourceRole` is the field that says which side you are on.** `TARGET` means the
resource was attacked; `ACTOR` means it was the one doing the attacking — and the second is a
compromised host in your own estate. Rules that ignore it treat both identically.

**Sample findings are prefixed `[SAMPLE]`** in the finding type and carry fictitious detail. Any
rule that does not exclude them will fire on a console demonstration.

## 5. What GuardDuty consumes, and the dependency that creates

GuardDuty's foundational data sources are CloudTrail management events, CloudTrail S3 data events,
VPC Flow Logs and DNS logs — and it consumes them **directly from AWS**, not from the customer's
copies. But the DNS findings depend on Route 53 Resolver query logging being available for the VPC,
and the EKS findings depend on EKS audit log monitoring being enabled.

So a technique that disables one of those sources degrades GuardDuty as well —
`techniques/vpc.stealth.no-logs-from-amazon-vpc-flow-logs/` and
`techniques/route53dns.stealth.no-logs-from-amazon-route53-dns-query/` both note it. **After such
an event, GuardDuty's silence carries no information.**

## 6. Where the control plane lives

`guardduty.amazonaws.com` in CloudTrail: `DeleteDetector`, `UpdateDetector` (this disables the
detector or its features), `CreateFilter` / `UpdateFilter` with `action: ARCHIVE` (a suppression
rule), `ArchiveFindings`, `DisassociateFromMasterAccount`, `DeleteMembers`,
`UpdateMemberDetectors`, `CreateIPSet` / `UpdateIPSet` (a trusted-IP list — **addresses on a
trusted IP list generate no findings at all**).

`CreateIPSet` deserves particular attention: a trusted IP list is a legitimate feature and an
excellent place to hide, because it suppresses findings at the source rather than archiving them
afterwards.

## 7. MITRE ATT&CK — checked live 2026-08-30

| ID | Status | Name | Tactic |
|---|---|---|---|
| `T1685` | live | Disable or Modify Tools | Defense Impairment |
| `T1685.002` | live | Disable or Modify Tools: Disable or Modify Cloud Log | Defense Impairment |
| `T1078` | live | Valid Accounts | Multiple |
| `T1526` | live | Cloud Service Discovery | Discovery |

`T1685` is the correct mapping for disabling a security *tool* such as GuardDuty, as distinct
from `.002` for disabling a *log*.

## 8. What could NOT be verified

1. **The EventBridge notification frequency for subsequent occurrences of an aggregated finding.**
   AWS documents the aggregation behaviour and a configurable notification frequency exists, but
   the default value was not confirmed on the pages audited. Rules here do not depend on it, and
   any statement about "how often a repeat fires" is avoided rather than guessed.
2. **Whether `service.archived` appears on the EventBridge event for a finding archived by a
   suppression rule**, or whether such findings are simply never delivered. The shipped rules treat
   the field as authoritative when present and do not rely on its absence.

**Correction, 2026-08-30.** An earlier version of this file named `T1685.001` as "Disable or Modify Cloud Security Tools". That sub-technique does not exist. `T1685`'s real sub-techniques are `.001` Windows Event Log, `.002` Cloud Log, `.003` Modify or Spoof Tool UI, `.004` Linux Audit System Log, `.005` Clear Windows Event Logs and `.006` Clear Linux or Mac System Logs. Disabling a cloud security service maps to the **parent** `T1685`, whose description covers "endpoint detection and response (EDR) tools, intrusion detection systems (IDS), antivirus, logging agents, sensors".
