# Detection Note — T1498 (Network Denial of Service)

**Signal:** sustained TCP SYN traffic to one destination — either from many distinct sources with
few packets each, or from a handful of sources with enormous packet volume.

**Those are two shapes of one attack, and a single rule cannot see both.** A distributed flood is
detected by source fan-out; a concentrated one produces almost no fan-out and is detected by
packet volume. Shipping only one leaves half the technique undetected, which is why there are two
correlations rather than one with a compromise threshold.

**What the original rule got wrong** — four parameters, three of which measure something other
than what they name.

*`tcp-flags: "2"` is an exact match on an OR-ed field.* AWS: *"TCP flags can be OR-ed during the
aggregation interval. For short connections, the flags might be set on the same line in the flow
log record, for example, 19 for SYN-ACK and FIN, and 3 for SYN and FIN."* A SYN flood is nothing
but short connections. Its records carry 3, 6, 7, 18, 19, 22 or 23 far more often than a clean 2,
so the rule matches the tidy minority and misses the flood. The correct test is *the SYN bit is
set* — `binary_and(flags, 2) != 0`, or the enumerated set where a backend has no bitwise operator.

*A threshold of 999 counts records, not traffic.* A flow log record is an **aggregate** over the
interval, carrying `packets` and `bytes`. One record can represent a hundred thousand packets. So
the threshold measures how many distinct 5-tuples appeared: a spoofed-source flood clears it
trivially while a single-source flood saturating a link may never reach it. Sum `packets`.

*A 5-minute window on a 10-minute aggregation interval.* The default maximum aggregation interval
is 10 minutes and delivery is *"about 5 minutes"* to CloudWatch Logs, best effort. A 5-minute
window sees zero buckets or one, so any count tuned against it is measuring bucket alignment.

*`action: REJECT` restricts to the flood that was already absorbed.* A flood the security group
blocked is the less damaging case; one that reaches the target and consumes its connection table
is the incident. Both are kept, and the accept/refuse split is read as an indicator rather than a
filter.

## `tcp-flags` is a version 3 field, and this is the failure mode that produces silence

The default flow-log format is version 2 and does not contain `tcp-flags`. AWS states the format
is fixed for the life of the subscription — *"you can't change its configuration or the flow log
record format... Instead, you can delete the flow log and create a new one"*. Against a
default-format subscription, every rule here that reads the field matches nothing.

The KQL treats a null `tcp-flags` as **"this subscription cannot answer the question"** rather
than as "no flags were set", and surfaces it as its own verdict line. Those two are not the same
thing and conflating them turns a configuration gap into a false all-clear.

## ACK is not recorded, so the textbook test does not exist

AWS: *"since `tcp-flags` does not support logging ACK or PSH flags, records for traffic with these
unsupported flags will result in `tcp-flags` value 0."* The classic half-open definition — SYN
seen, ACK never seen — is therefore describing a field that is not in the log. Any rule phrased
that way is matching on an absence that carries no information.

The half-open character has to be inferred instead, and the KQL does it with packets-per-source: a
completed connection exchanges more than a handful of packets and a half-open one does not. That
is an inference, and it is labelled as one.

## Response levers

**The two shapes have different containment.** A concentrated flood from a few addresses can be
dropped at a network ACL, which is stateless and evaluates before security groups. A distributed
flood cannot — blocking addresses will not keep up with a botnet, and the sources are spoofed
anyway, so a blocklist built from them may block nobody and somebody else. That case is AWS
Shield and the load balancer's own absorption, not a rule change.

**Under-counting during a flood is the expected failure.** `log-status: SKIPDATA` means AWS
dropped records *"because of an internal capacity constraint, or an internal error"* — and a
traffic flood is precisely when that becomes likely. Read every number in this playbook as a
floor, never as a measurement.

**Flow logs cannot tell you the service degraded.** They record what arrived at the interface, not
what the application did with it. Target health, load balancer 5xx rates and application latency
answer that; the ALB 5xx-rate use case (not in this set) is the adjacent view when
the target sits behind an Application Load Balancer.

**`pkt-dstaddr`, not `dstaddr`.** AWS: for traffic to an interface whose destination is not one of
that interface's addresses, the log shows *"the primary private IPv4 address"*. Behind a Network
Load Balancer every target collapses to the balancer's interface, and the alert names the wrong
host — which during an availability incident sends the response to the wrong team.

**MITRE:** `T1498 — Network Denial of Service`, the source's mapping, kept. Verified live
2026-08-30.

**Severity:** high for either confirmed shape. Availability rather than confidentiality, but a
saturated connection table takes the service down as completely as anything in this corpus.

**GuardDuty:** partial and indirect. `Backdoor:EC2/DenialOfService.*` fires when *your* instance
is the one participating in an outbound flood, which is the opposite direction from this playbook.
There is no GuardDuty finding for inbound volumetric attack; AWS Shield Advanced is the product
that covers it, and its detection is independent of flow logs.

**Files here:**
- `sigma_t1498.yml` — three documents: `vpc_syn_volume` (informational base rule, the enumerated
  SYN-bit set), a `value_count` correlation on distinct sources per target (high, the distributed
  shape), and an `event_count` correlation per source-target pair (high, the concentrated shape).
- `kql_t1498.kql` — the packet-summing view, with `binary_and` for the flag test and a
  `FieldMissing` column that distinguishes "no SYNs" from "this subscription has no flag field".

Full response procedure is in `../PLAYBOOK.md`.
