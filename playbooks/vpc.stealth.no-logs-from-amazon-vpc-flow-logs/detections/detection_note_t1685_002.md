# Detection Note — T1685.002 (Disable or Modify Tools: Disable or Modify Cloud Log)

**Signal:** a VPC flow log subscription deleted, recreated without the standard fields, or pointed
at a destination that no longer exists.

**An absence alert's input is precisely what the attacker removed.** That is the structural
problem with the source rule and it cannot be tuned away. The corrected set moves the detection to
the control plane, where the act is recorded, attributed to a principal, and timestamped — and
keeps the absence view as a corroborator that says which resource stopped, never as the alert.

## Why the source rule cannot be the control

It fires when fewer than one flow record arrives in two hours, grouped by nothing. Four things
produce an empty window and only one is an incident:

1. **The subscription was deleted** — `DeleteFlowLogs` records it directly, with a principal.
2. **The destination was removed** — `DeleteLogGroup` records that, and the subscription keeps
   reporting `ACTIVE` while nothing lands.
3. **Delivery is lagging** — AWS gives *"about 5 minutes"* to CloudWatch Logs and *"about 10
   minutes"* to Amazon S3, and states delivery *"is on a best effort basis"*. No maximum is
   published, so a gap is never conclusive in either direction.
4. **There was genuinely no traffic** — and this case still produces records, because `log-status:
   NODATA` means *"there was no network traffic to or from the network interface during the
   aggregation interval"*.

Point 4 is worth restating: **presence of records is not presence of observation.** An idle
interface emits records saying nothing happened, so a count cannot distinguish a healthy quiet
resource from a healthy busy one, and it cannot use record presence as evidence that logging works.

**And the empty `group_by` makes it worse the larger the account.** The rule counts every flow
record in the account, so deleting one VPC's subscription among several changes the total by a
fraction and the rule never fires. The blind spot scales with everything else that is still
logging.

**A fifth state is invisible to it entirely.** `SKIPDATA` means AWS *"skipped"* records *"because
of an internal capacity constraint, or an internal error"*. Partial loss produces records, so a
presence check reports healthy while an unknown fraction of traffic is missing — and this is the
likeliest failure mode during a traffic flood, which is exactly when the records matter.

## The downgrade is the quiet attack, and also the common accident

A subscription's format cannot be edited. AWS: *"After you create a flow log, you can't change its
configuration or the flow log record format... Instead, you can delete the flow log and create a
new one with the required configuration."*

So delete-then-recreate is ordinary maintenance **and** the mechanism by which a custom format
becomes the version 2 default — a `CreateFlowLogs` that simply omits `logFormat` takes the default
silently. Afterwards records arrive at the same rate, every absence rule stays quiet, AWS Config
shows a healthy resource, and every detection reading `tcp-flags`, `pkt-srcaddr`, `pkt-dstaddr` or
`flow-direction` stops matching at once. Nothing is missing except the fields.

`ec2_flow_logs_created_downgraded` therefore matches the **absence** of the required fields in the
request, which catches both the short custom format and the omitted one.

## Retention is a third path to the same outcome

The CloudWatch Logs default is Never Expire, so a `PutRetentionPolicy` on a flow log group is
always a deliberate act. Cutting it to a day destroys history without touching a single flow log
API, and leaves the subscription reporting `ACTIVE`. The number chosen is how many days of network
history the organisation will have during its next incident, and that decision should not be made
silently.

## Response levers

**State beats absence, and neither log carries it.** `describe-flow-logs` returns `FlowLogStatus`
and `DeliverLogsErrorMessage` per subscription. A subscription whose delivery role lost its
permissions reports `ACTIVE` with an error message and delivers nothing — and **no CloudTrail
event marks the moment it started failing**, because nothing was called. Only a scheduled read of
that state finds it.

**AWS Config records `AWS::EC2::FlowLog`**, which gives configuration history for the subscription
including its format. That is the one source that can answer "what fields did this have last
month", and it is worth enabling before it is needed.

**There is no flow-log-specific event source.** `CreateFlowLogs`, `DeleteFlowLogs` and
`DescribeFlowLogs` are `ec2.amazonaws.com`, so a trail filtered narrowly by service will not have
them unless EC2 is included.

**MITRE:** `T1685.002 — Disable or Modify Cloud Log` is the correct current ID and describes
this exactly. Verified live 2026-08-30.

**Severity:** high for a deletion, high for a downgrade — the second is rated equally on purpose,
because it is less visible and lasts longer. Medium for destination and retention tampering, which
are equally effective and more often accidental.

**GuardDuty:** no coverage. There is no finding type whose resource is a flow log subscription.
GuardDuty *consumes* VPC flow logs as a data source, which means this technique degrades GuardDuty
too — a fact worth stating in the incident, because "GuardDuty is quiet" stops being reassurance
once the flow logs it reads are gone.

**Files here:**
- `sigma_t1685_002.yml` — three CloudTrail documents: `ec2_flow_logs_deleted` (high),
  `ec2_flow_logs_created_downgraded` (medium), `flow_log_destination_tampered` (medium).
- `kql_t1685_002.kql` — the control-plane view with a downgrade test, plus the per-resource
  absence view in a commented section with the four-states argument beside it.

Full response procedure is in `../PLAYBOOK.md`.
