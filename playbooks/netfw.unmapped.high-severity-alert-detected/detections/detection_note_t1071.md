# Detection Note — T1071 (Application Layer Protocol) / T1190 (Exploit Public-Facing Application)

**Signal:** a stateful rule with Suricata severity 1 alerted, and the firewall did not block the
traffic.

**Severity 1 is the most severe, and the source pack has this right.** Suricata's scale is
inverted relative to intuition. The pack maps 1 to high, 2 to medium and 3/4 to low, which is
correct — recorded here because the reviewer's instinct is to "fix" it, and doing so would silently
invert the entire alert hierarchy.

**What the original rule got wrong** — it filters out the blocked half.

`(action:"allowed" OR NOT action:"blocked")` keeps only traffic the firewall let through. As a
paging decision that is defensible. As a detection it costs two things: the ability to distinguish
*"nobody is attacking us"* from *"everything is being blocked"*, and the entire probing run-up in
which an actor is refused repeatedly before finding a path that passes. The corrected set keeps
both and separates them by **rule level** — unblocked at high to a person, blocked at low to a
dashboard — so the routing is explicit and the second stream still exists.

The construct is also redundant. With `alert.action` taking `allowed` or `blocked`, `allowed OR NOT
blocked` reduces to `allowed`, plus any record where the field is absent.

And the companion medium-severity rule in the same pack has an **empty `group_by` with a threshold
of zero**: every individual alert pages, with no aggregation and no actor.

## Two action fields, answering different questions

`alert.action` is what the alerting rule reports. `event.verdict.action` is the packet's
disposition. AWS's own examples carry `"action":"allowed"` on one record and `"action":"blocked"`
with `"verdict":{"action":"drop"}` on another. Where both are present and disagree, **the verdict
is what happened** — and the KQL projects both with a `Disagree` counter, so a disagreement is
something a responder sees rather than something they inherit.

## The alert log is a filtered view, twice over

**Only `DROP`, `ALERT` and `REJECT` produce alert entries.** AWS: *"A stateful rule sends alerts for
the rule actions DROP, ALERT, and REJECT."* A `PASS` rule produces none, so traffic that matched an
explicit pass is in the flow log and nowhere in the alert log.

**And the stateless engine produces nothing at all.** AWS: *"Firewall logging is only available for
traffic that you forward to the stateful rules engine."* Traffic a stateless rule dropped leaves no
alert entry, no flow record, nothing but CloudWatch metrics. So the absence of an alert is never
evidence that traffic did not arrive — it may have been handled before the engine that logs ever
saw it.

Both facts point the same way: the alert log describes the traffic the policy chose to inspect, not
the traffic that reached the firewall.

## Response levers

**`aws_metadata.resource_arn` is the fastest triage field.** AWS: *"The Amazon Resource Name (ARN)
of the rule group or firewall policy that generated the alert."* A severity-1 signature passing
traffic is usually a rule group still in alert-only evaluation mode, and the ARN says which one in
one hop.

**Signature breadth separates an actor from a noisy rule.** A scanner trips the same signature
repeatedly; an actor working through an estate trips different ones as they move through
reconnaissance, exploitation and command-and-control. The correlation counts distinct
`signature_id` per source for that reason, and its most common cause is your own vulnerability
scanner — which is worth confirming by schedule rather than assuming.

**Encrypted flows may have been matched on the envelope only.** `tls_inspected` is **omitted**, not
set to `false`, when TLS inspection did not apply. Where it is absent, the alert matched on SNI,
addresses or flow characteristics — so a clean result means the envelope looked clean and says
nothing about the payload.

**MITRE:** the source pack maps this rule to nothing. `T1071 — Application Layer Protocol` is the
tactic-level anchor for the command-and-control shape most severity-1 signatures carry, and
`T1190 — Exploit Public-Facing Application` on the breadth correlation. A severity-based rule spans
many techniques by construction, so these are anchors rather than a claim about any single alert —
the signature name in the record is what actually identifies the technique. Both verified live
2026-08-30.

**Severity:** high for an unblocked severity-1 alert, medium for signature breadth, low for the
blocked stream. The blocked stream's *volume* and its sudden *absence* are both signals; its
presence is not.

**GuardDuty:** no overlap. GuardDuty does not consume Network Firewall logs, and its network
findings derive from VPC flow logs and DNS logs. The two are independent views, which makes
agreement between them meaningful.

**Files here:**
- `sigma_t1071.yml` — three documents: `netfw_high_severity_unblocked` (high),
  `netfw_high_severity_blocked` (low, deliberately kept rather than filtered), and a `value_count`
  correlation on distinct signatures per source (medium).
- `kql_t1071.kql` — blocked and unblocked separated in the output, with `alert.action` and
  `verdict.action` both projected and a `Disagree` counter between them.

Full response procedure is in `../PLAYBOOK.md`.
