# Detection Note — T1071 (Application Layer Protocol) / T1041 (Exfiltration Over C2 Channel)

**Signal:** an outbound flow lasting an hour or more and carrying substantial volume at a low rate
— or, the shape this rule is named for and cannot see, many short flows at a near-constant interval.

**The rule's name and its logic describe different things.** `age >= 3600 AND bytes >= 5,000,000`
is roughly 1.4 KB/s: low *rate*, substantial *volume*. That is slow exfiltration over a persistent
connection, and it is a worthwhile detection. But **beaconing** — which "low-throughput egress"
names — is the opposite shape: many short flows at regular intervals, each a few hundred bytes.
Every one of those has an age near zero and a byte count orders of magnitude below the threshold.
The rule cannot see it. Both are shipped here, because both are real and the pack has a rule for
only one.

**What else the original rule got wrong**

*`netflow` is uni-directional, so `bytes` is one leg.* AWS: *"The log type `netflow` logs
uni-directional flows, so each event represents traffic going in a single direction."* A large
download and a large upload produce matching records and only one is exfiltration. The corrected
rules read `event.direction` — `to_server` is outbound — instead of inferring intent from volume.

*Geo-enrichment stands in for "external"* where the destination address answers directly, and makes
the rule depend on a pipeline that may not exist.

*A threshold of zero grouped only by source* means every matching flow alerts individually rather
than per source-destination pair, which is the unit an analyst actually acts on.

## The alert is structurally late, and no window fixes it

Netflow records are emitted when a flow **ends** or times out, not continuously. A flow matching
`age >= 3600` therefore produces its record at least an hour after it started — so the source
rule's 10-minute window is a window on *record arrival*, not on traffic. By the time the
slow-exfiltration verdict fires, the data has moved.

This is a property of the log format, and the shipped files state it rather than tuning around it.
The value of this detection is **scoping the loss**, not preventing it, and a playbook that implies
otherwise sets the wrong expectation for the response.

Beaconing is the opposite case: each flow is short, so records arrive continuously and the
correlation can fire while the channel is still live. That is the one of the two shapes where fast
detection is actually available.

## Interval regularity is the beacon discriminator, and it lives in the KQL

Counting flows per source-destination pair surfaces the candidate. What separates a beacon from a
busy client is the **regularity of the interval**: the standard deviation of the gaps between flow
starts, divided by their mean. A beacon's interval is near-constant, so the ratio is very small.

Sigma correlations have no variance operator, so the Sigma rule counts and the KQL computes the
regularity. That split is deliberate rather than an omission, and it is stated in the rule's own
description.

The measure narrows rather than settles: monitoring agents, telemetry SDKs and health checks are
regular by design and will dominate the low-regularity rows. The destination — its SNI, its port,
whether anyone can name it — is what decides.

## Response levers

**The stateless engine is invisible.** AWS: *"Firewall logging is only available for traffic that
you forward to the stateful rules engine."* Absence of a netflow record is not evidence that no
transfer occurred; it may have been handled before the engine that logs.

**Netflow is a counter, not a capture.** Bytes and packets, no payload. Where `app_proto` is `tls`
and `tls_inspected` is absent, the SNI may be everything that is known about the destination — and
`tls_inspected` is **omitted** rather than set to `false` when inspection did not apply.

**Tune by destination, not by threshold.** Backups, log shipping, container image pulls and update
channels all produce long-lived high-volume outbound flows. Raising the byte threshold moves the
line and loses the slow transfers; naming the known destinations removes the noise and keeps them.

**MITRE:** the source carries bare `T1071`. `T1041 — Exfiltration Over C2 Channel` is added for the
slow-transfer rule, which observes data leaving rather than a channel existing;
`T1071 — Application Layer Protocol` stays on the beaconing correlation. Both verified live
2026-08-30.

**Severity:** medium on the individual rules, because the false-positive surface is genuinely
large. The KQL escalates to P0 verdicts where the two measures combine — beaconing with a regular
interval and low volume, or a long flow at a low rate — which is where the shape stops being
explicable by ordinary infrastructure.

**GuardDuty:** partial and independent. `Trojan:EC2/DNSDataExfiltration` and the
`Backdoor:EC2/C&CActivity` family cover related behaviour from VPC flow logs and DNS logs, not from
Network Firewall. The two sources are independent, so agreement between them is meaningful and
GuardDuty's silence here says nothing about this traffic.

**Files here:**
- `sigma_t1071.yml` — three documents: `netfw_slow_egress_flow` (medium, the corrected version of
  the source rule), `netfw_egress_flow` (informational base rule) and an `event_count` correlation
  for beaconing candidates (medium).
- `kql_t1071.kql` — both shapes in one view, with interval regularity computed from the gaps
  between flow starts and the late-alert property stated.

Full response procedure is in `../PLAYBOOK.md`.
