# Detection Note — T1685.002 (Disable or Modify Tools: Disable or Modify Cloud Log)

**Signal:** a Network Firewall logging configuration emptied, or a firewall policy changed so
stateless defaults no longer forward traffic to the stateful engine.

**Absence is a worse control in this service than in any other in the corpus, for a reason that is
permanent rather than transient.** AWS: *"Firewall logging is only available for traffic that you
forward to the stateful rules engine."* A policy whose stateless default action is `aws:drop` or
`aws:pass` produces no alert log and no flow log — correctly, by design, and forever. An absence
rule fires on that configuration continuously. Elsewhere the false positive is a quiet hour; here it
is a valid configuration that will never stop tripping the rule.

**What the original rule got wrong** — beyond that, two structural problems.

*The `group_by` is empty.* An account-wide record count barely moves when one firewall goes dark.
Firewalls are per-endpoint resources, so the firewall is the unit of coverage and it is exactly what
the rule cannot name.

*It looks for records stopping, and the API cannot express what it needs anyway.* Logging is a
configuration **on** the firewall rather than a separate resource, so there is no delete verb.

## The API records the survivors, never the casualty

`UpdateLoggingConfiguration` **replaces** the whole configuration. Removing the alert log type and
removing every log type are the same API call, and the request carries the **remaining**
destinations. So:

- A rule matching *"the alert type was removed"* matches nothing — the removed type is precisely
  what the event does not contain.
- An empty `logDestinationConfigs` list **is** the removal, and that is matchable.
- A **partial** removal — alert logging dropped, flow logging kept — is indistinguishable in the
  event from a routine destination change.

The shipped rules therefore match the empty case directly and route the partial case to a state
comparison, which is a read of `describe-logging-configuration` against a stored previous value.
That comparison needs history to exist beforehand, which is why §1 asks for a scheduled snapshot
rather than treating it as an incident-time query.

## The third path, which leaves the dashboards green

Changing the firewall policy so stateless defaults omit `aws:forward_to_sfe` achieves everything
disabling logging achieves, and more: the traffic is no longer inspected either. Every console view
still shows logging enabled with destinations configured. Nothing about the logging configuration
changed, because nothing needed to.

`netfw_stateless_forward_removed` covers it, and it is shipped at the same level as the outright
removal because it is strictly worse — it removes the control as well as the record.

## Response levers

**State beats absence, and it is the only thing that resolves a partial removal.**
`describe-logging-configuration` returns the current log types and destinations per firewall. Since
the CloudTrail event shows survivors rather than removals, this read against a stored previous value
is the only way to know which type disappeared.

**Two more reasons for a quiet log that are not incidents.** Alert logs exist only for `DROP`,
`ALERT` and `REJECT` actions, so a quiet alert log alongside a busy flow log is normal — a policy
whose matches are mostly `PASS` produces exactly that. And an endpoint with no traffic produces
nothing at all.

**MITRE:** Verified live 2026-08-30.

**Severity:** high for an emptied configuration and for stateless defaults dropping
`aws:forward_to_sfe`, medium for any other logging change — which is deliberately broad, because
its job is to trigger the state comparison rather than to decide on its own.

**GuardDuty:** no coverage. GuardDuty does not consume Network Firewall logs and has no finding
type for a firewall's logging configuration. Unlike the VPC and DNS cases, disabling this logging
does not degrade GuardDuty — the two are independent, which is worth knowing because it means
GuardDuty's continued silence during such a gap genuinely carries no information about it either way.

**Files here:**
- `sigma_t1685_002.yml` — three CloudTrail documents: `netfw_logging_removed` (high, the empty
  configuration), `netfw_logging_configuration_changed` (medium, deliberately broad to trigger the
  state comparison), and `netfw_stateless_forward_removed` (high, the path that leaves dashboards
  green).
- `kql_t1685_002.kql` — both control-plane paths in one view, with the surviving log-type count
  projected and the absence view's five explanations set out beside it.

Full response procedure is in `../PLAYBOOK.md`.
