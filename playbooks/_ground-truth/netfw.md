# Ground truth — AWS Network Firewall logging

Audited 2026-08-30 against the AWS Network Firewall Developer Guide (*Logging network traffic*,
*Contents of a log*). Every playbook under `techniques/netfw.*` is written from this file.

---

## 1. The sentence that bounds every rule in this service

> **Firewall logging is only available for traffic that you forward to the stateful rules engine.**
> You forward traffic to the stateful engine through stateless rule actions and stateless default
> actions in the firewall policy.

**Traffic the stateless engine handles produces no log entry at all.** A stateless rule that drops
a packet, or a stateless default action that drops, leaves nothing in the alert log, nothing in the
flow log, and nothing anywhere else — only CloudWatch metrics, which AWS notes *"provide some
higher-level information for both stateless and stateful engine types"*.

So the log is a view of the traffic the policy chose to inspect, not of the traffic that arrived.
Every count in this service is bounded by that choice, and an absence rule is measuring the
stateful engine's throughput rather than the firewall's.

## 2. Three log types, and which rule actions produce them

> - Flow logs are standard network traffic flow logs.
> - Alert logs report traffic that matches your stateful rules that have an action that sends an
>   alert. **A stateful rule sends alerts for the rule actions `DROP`, `ALERT`, and `REJECT`.**
> - TLS logs report events that are related to TLS inspection. These logs require the firewall to
>   be configured for TLS inspection.

**`PASS` produces no alert log entry.** So allowed traffic that matched an explicit pass rule is
absent from the alert log and present only in the flow log — and a rule reading the alert log to
mean "everything the firewall saw" is reading a filtered subset by design.

**Logging is enabled after the firewall is created**, per log type, and each type can go to a
different destination. Nothing about a firewall existing implies its traffic is recorded.

## 3. Record shape — Suricata EVE JSON with AWS additions

Top-level: `firewall_name`, `availability_zone`, `event_timestamp` (**epoch seconds**),
`aws_category` (URL/domain category filtering, a JSON array *as a string*), and `event`.

> Alert and flow events are produced by Suricata... Suricata writes the event information in the
> Suricata EVE JSON output format... Flow log events use the EVE output type `netflow`. **The log
> type `netflow` logs uni-directional flows, so each event represents traffic going in a single
> direction.** Alert log events using the EVE output type `alert`.

Inside `event`: `timestamp` (ISO 8601, distinct from the epoch `event_timestamp` above), `flow_id`,
`event_type`, `src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `app_proto`, `direction`
(`to_server` / `to_client`), `tx_id`, `pkt_src`, and for alerts an `alert` object:

`alert.action`, `alert.signature_id`, `alert.rev`, `alert.signature`, `alert.category`,
`alert.severity`, `alert.metadata.container_association`.

AWS adds `event.aws_metadata.resource_arn` — *"The Amazon Resource Name (ARN) of the rule group or
firewall policy that generated the alert"* — and `event.verdict.action`, and
`"tls_inspected": true` when TLS inspection applied (**omitted**, not `false`, when it did not).

**`alert.action` and `verdict.action` are different fields answering different questions.** In
AWS's own examples an alert carries `"action":"allowed"` on one record and `"action":"blocked"` with
`"verdict":{"action":"drop"}` on another. Treat `alert.action` as what the alerting rule reports and
`verdict.action` as the disposition; where both are present and disagree, the verdict is the packet's
fate.

## 4. Severity is inverted, and the source pack gets this right

Suricata severity is **1 = most severe**, ascending to less severe. The source rules map
`severity: 1` to high, `2` to medium and `3`/`4` to low, which is correct — worth stating
explicitly because the inversion is a common error and a reviewer's instinct is to "fix" it.

## 5. `netflow` is uni-directional, and this breaks volume rules quietly

Because *"each event represents traffic going in a single direction"*, `event.netflow.bytes` is one
direction of a conversation. A rule grouped by `(src_ip, dest_ip)` without also keying on direction
merges the request and response legs of different flows, or reports only one leg as if it were the
transfer. Any egress-volume rule must either filter on direction or state that it is measuring one
leg.

`event.netflow.age` is the flow's duration in seconds, which is what makes long-lived low-rate
sessions detectable at all.

**Timing caveat:** netflow records are emitted when a flow ends or times out, not continuously. A
transfer running for hours produces its record at the end, so a short evaluation window can miss a
flow entirely and then see all of it at once. Thresholds in this service are windowed accordingly
and the effect is stated where it matters.

## 6. TLS log events

Produced by a dedicated engine, not Suricata, with a similar JSON shape. Two error classes:

- `tls_error` — *"Currently, this category includes Server Name Indication (SNI) mismatches and SNI
  naming errors... For example, errors caused when the client hello SNI is NULL or doesn't match the
  subject name in the server certificate."*
- `revocation_check` — `{leaf_cert_fpr, status, action}`, reporting outbound traffic that fails the
  server certificate revocation check. Requires outbound TLS inspection **and** revocation checking
  to be configured.

A NULL or mismatched SNI is the shape of domain fronting and of a client deliberately hiding its
destination, which makes `tls_error` more interesting than its name suggests.

## 7. Where the control plane lives

`network-firewall.amazonaws.com` in CloudTrail: `UpdateLoggingConfiguration` (this is how logging is
turned off — it is a configuration on the firewall, not a separate resource),
`DeleteFirewall`, `UpdateFirewallPolicy`, `DeleteRuleGroup`, `UpdateRuleGroup`,
`AssociateFirewallPolicy`, `UpdateFirewallDeleteProtection`.

**`UpdateLoggingConfiguration` replaces the whole configuration**, so removing one log type is the
same call as removing all of them, and the request carries the surviving set rather than the removed
one. A rule looking for a "delete" verb finds nothing.

## 8. MITRE ATT&CK — checked live 2026-08-30

| ID | Status | Name | Tactic |
|---|---|---|---|
| `T1685.002` | live | Disable or Modify Tools: Disable or Modify Cloud Log | Defense Impairment |
| `T1041` | live | Exfiltration Over C2 Channel | Exfiltration |
| `T1071` | live | Application Layer Protocol | Command and Control |
| `T1071.001` | live | Application Layer Protocol: Web Protocols | Command and Control |
| `T1133` | live | External Remote Services | Initial Access, Persistence |
| `T1573` | live | Encrypted Channel | Command and Control |
| `T1090` | live | Proxy | Command and Control |

## 9. What could NOT be verified

1. **The exact emission timing of netflow records** beyond "flow end or timeout". AWS does not
   publish the timeout values used by the managed stateful engine.
2. **Whether `alert.action` can be `blocked` while `verdict.action` is absent.** Both appear in
   AWS's examples; the relationship is inferred from those rather than stated.
3. **Whether `aws_category` is present on all alert types or only when URL/domain category filtering
   is configured.** AWS's example shows it under that configuration only.
