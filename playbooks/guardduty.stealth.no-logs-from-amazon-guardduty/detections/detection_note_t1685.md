# Detection Note — T1685 (Disable or Modify Tools)

**Signal:** the GuardDuty detector deleted or disabled, a suppression rule created, or a trusted IP
list changed.

**The rule this replaces alerts when the account is secure.** It fires when fewer than one finding
arrives in 36 hours — and GuardDuty emits a finding only when it *detects* something. An account
with nothing wrong emits none, for days, correctly. AWS defines even the lowest band as *"attempted
suspicious activity that did not compromise your environment"*, which is a property of
internet-facing estates and not of quiet internal ones.

This is a stronger objection than the one that applies to the other no-logs rules in this corpus.
Those detect a real gap and cannot attribute it; this one's **firing condition is the desired
state**. No window length fixes it — a longer window makes the rule slower without making it right.
A team running it learns that the GuardDuty alert means nothing, which is precisely the state they
are in on the day the detector is actually turned off.

**So this playbook ships no absence view at all**, which is a deliberate departure from every other
`*.stealth.no-logs-*` playbook here. The signal is the act, and the corroborator is a state read of
the detector rather than a query over findings.

## Three ways to go blind, and the quietest is a documented feature

**Delete or disable the detector.** Loud, and the one an absence rule would eventually catch. Note
that `UpdateDetector` is the same event name for enabling and disabling, so the parameters are the
discriminator — and GuardDuty is **regional**, so disabling it in one Region leaves every other
Region reporting normally and an account-wide dashboard looking healthy.

**Create a suppression rule** — a filter with an `ARCHIVE` action. Matching findings are still
generated and then archived automatically. The detector is healthy, the finding volume looks
normal, and the suppressed class reaches nobody. This is a necessary feature for tuning out
known-benign activity, which is exactly why it is worth alerting on: the same mechanism tunes out
an attacker.

**Add a trusted IP list.** Findings for those addresses are **never generated** — not created and
archived, never created. Nothing in the finding stream can reveal it, no count changes, and the
console shows a working detector with an unbroken history. The rules here treat it at the same
level as deleting the detector.

One detail makes the trusted IP list worse than it first appears: the `CreateIPSet` event carries a
`Location` — an S3 object URI — and **not the addresses**. An attacker who can write to that object
can change the trusted set without making any further GuardDuty API call at all, so the detection
must be paired with monitoring of the object itself.

## A fourth path that is not a GuardDuty action

GuardDuty's DNS findings depend on Route 53 Resolver query logging being available for the VPC, and
its EKS findings on EKS audit log monitoring. Disabling either blinds GuardDuty **without touching
GuardDuty** and produces nothing in its own control-plane trail.
`../../route53dns.stealth.no-logs-from-amazon-route53-dns-query/` and
`../../eks.stealth.user-deleted-log-events/` cover those, and this playbook names the dependency so
it is not rediscovered mid-incident.

## Response levers

**The detector's status is a state read, not a log query.** `get-detector` returns it, per Region,
and it is the only reliable answer to "is GuardDuty on right now". A scheduled read with stored
history is what turns a suppression rule created three months ago into something findable.

**Read the criteria and the list, not just the call.** A filter's `FindingCriteria` is in the event;
a trusted IP list's contents are not. Triage of the second requires fetching the S3 object.

**MITRE:** The
sub-technique matters here: `T1685` is the parent, for disabling a security **tool**, and `T1685.002` is for a
**log**. GuardDuty is a tool, which is why this playbook uses `.001` while every other
`*.stealth.no-logs-*` playbook in this corpus uses `.002`. Verified live 2026-08-30.

**Severity:** high for all three paths. The trusted-IP-list path is rated equal to deletion
deliberately — it is quieter, it is invisible to finding-stream monitoring, and it is more
selective, which makes it more useful to an attacker than turning the service off.

**GuardDuty:** no self-coverage. GuardDuty does not produce a finding when GuardDuty is disabled,
for the obvious reason. CloudTrail is the only source, which is why every rule here reads it.

**Files here:**
- `sigma_t1685.yml` — three CloudTrail documents: `guardduty_detector_disabled` (high),
  `guardduty_suppression_filter_created` (high), `guardduty_trusted_ip_set_changed` (high).
- `kql_t1685.kql` — all three paths in one view, with the parameters that distinguish enabling
  from disabling, and an explicit note on why no absence view is included.

Full response procedure is in `../PLAYBOOK.md`.
