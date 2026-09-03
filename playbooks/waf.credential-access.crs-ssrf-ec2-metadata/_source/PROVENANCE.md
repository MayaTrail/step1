# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, threshold, window, group-by keys and MITRE labels |
| Scope captured | Four alerts — the Core-rule-set EC2 metadata SSRF family |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Threshold | Window | Group-by | Source MITRE label |
|-------|----------|------|-----------|--------|----------|--------------------|
| CRS SSRF EC2 Metadata URI Path | P2 | threshold | `> 0` | 5m | `httpRequest.clientIp` | T1552.005/TA0006 |
| CRS SSRF EC2 Metadata Cookie | P2 | threshold | `> 0` | 5m | `httpRequest.clientIp` | T1552.005/TA0006 |
| CRS SSRF EC2 Metadata Body | P2 | threshold | `> 0` | 5m | `httpRequest.clientIp` | **T1552**/TA0006 |
| CRS SSRF EC2 Metadata Query Args | P2 | threshold | `> 0` | 5m | `httpRequest.clientIp` | T1552.005/TA0006 |

A threshold alert with a threshold of `0` is a per-event alert wearing a volume shape: it fires on
the first matching document in the window.

## Merge decision — MERGE, under test 1

`07-TIERS.md` §"When merging is legitimate" test 1: *same observable, same response, differing only
in threshold or priority.* These four differ in **less** than that test allows.

**Same observable.** All four are one rule with one field varying. Line them up:

```
action:"ALLOW" AND labels_field_extracted.keyword:/.*EC2MetaDataSSRF_URIPath.*/
action:"ALLOW" AND labels_field_extracted.keyword:/.*EC2MetaDataSSRF_Cookie.*/
action:"ALLOW" AND labels_field_extracted.keyword:/.*EC2MetaDataSSRF_Body.*/
action:"ALLOW" AND labels_field_extracted.keyword:/.*EC2MetaDataSSRF_QueryArguments.*/
```

Identical priority, identical type, identical threshold, identical window, identical group-by key.
The only difference is the tail of one label, and all four labels are emitted by four rules of one
managed rule group inspecting one thing — *does this request try to reach `169.254.169.254`* — in
four request components. The observable is the attempt; the component is an attribute of it.

Stronger than that: **one request can carry more than one of the four labels**, because all four
CRS rules evaluate the same request and each adds its own label on match. A payload placed in both
the query string and the URI path produces two labels on one record and, under the source set, two
alerts for one request. Four separate rules do not merely duplicate the work — they misreport the
cardinality of the event.

**Same response.** Every step of §3–§5 is identical whichever component matched: confirm the
terminating action, read the web ACL's override state, identify the resource and the instance
profile behind it, block the client address, confirm IMDSv2 enforcement, hand off to the
credential-theft playbook. Nothing containment does differs by component. The one place the
component matters at all is the **body-size caveat**, which applies to `_Body` only — and that is a
paragraph scoped to one row of the trigger table, not a different response.

**What merging buys, concretely.** The count of *distinct components* per client address becomes
expressible, and it is the strongest single-window discriminator this telemetry offers: one
component is an opportunistic payload, two or more is deliberate enumeration of where the
application is injectable. Split four ways, that pattern arrives as unrelated alerts against the
same address and nothing joins them. It ships here as a `value_count` correlation at `high`.

**The component is not lost.** It is a column of §2's trigger table, a field on every query's
output, and a `Component` extracted from the matched label in the KQL.

Test 2 does not apply: none of the four is a correlation rule.

## Tier decision — TIER 1, promoted on tests 5 and 1

The catalogue proposes Tier 1 and it is earned twice over.

**Test 5 — the detection has a structural blind spot worth a page of honesty.** Three compounding
ones, and they are the reason this playbook exists rather than a rule fix: (a) the `action:"ALLOW"`
filter makes all four rules silent in the configuration where the Core rule set is doing its job,
and a blocked attempt raises nothing at all, so the queue is empty in both the healthy case and the
never-deployed case; (b) the alert observes an **attempt**, never an outcome — whether a credential
was returned is decided by the target instance's IMDSv2 setting, which appears in no web ACL log,
and the metadata fetch itself produces no AWS telemetry; (c) the body variant inspects only the
first 8 KB on an ALB and forwards the remainder intact, which is a live evasion rather than a
theoretical one. Any one of those would earn the section; together they are the playbook's spine.

**Test 1 — account takeover is reachable in one further hop.** The objective of a metadata SSRF is
the instance profile's temporary credentials. Where that profile carries IAM write permissions, the
next call after the fetch is the escalation, and the credential is usable from the actor's own
infrastructure with nothing to disable.

Test 3 also part-applies — the blast radius is not in the event, since the log names a client
address, a URI and a `httpSourceId`, and never the instance or the role behind it — but that is
retrievable after containment and is not load-bearing for the promotion.

## What was NOT merged, and why

| Considered | Verdict |
|------------|---------|
| `../../ec2.credential-access.imds-credential-theft/` | **Separate, and downstream.** That playbook owns the outcome: a role session used off-instance, the `ec2RoleDelivery` discriminator, session revocation and profile replacement. This one owns the inbound attempt at the edge, where the response is a WAF configuration question and an application-vulnerability question. The two are cross-referenced in both directions and neither repeats the other's ground truth |
| The source set's other CRS component families — `CRS LFI *`, `CRS RFI *`, `CRS XSS *` | **Separate.** Same four-way component split, same `ALLOW` defect, but a different observable with a different objective and a different response. Sharing a rule group is not grounds to merge, in the same way that sharing a MITRE technique is not |
| `../../waf.initial-access.known-bad-ip-with-allowed-web-attack-detected/` | **Separate.** Its regex includes `EC2MetaDataSSRF_` among eleven attack families, but the observable is the *conjunction* with an IP reputation label and its central finding is an evaluation-order one. It is not a volume variant of this rule |
| `../../waf.stealth.no-logs-from-aws-waf/` | **Separate, and a precondition.** Everything here depends on the web ACL having a logging configuration at all |

## MITRE label dispute — partial

The source labels three of the four **T1552.005 / TA0006** and the Body rule the bare parent
**T1552 / TA0006**, an inconsistency inside one set of four siblings. `T1552.005` — *Unsecured
Credentials: Cloud Instance Metadata API* — is retained as the primary for all four; it names the
objective exactly.

**T1190 — Exploit Public-Facing Application** is added as a genuine second mapping and is not in
the source. What the web ACL observes is a request against a public-facing application attempting
to induce a server-side fetch; the metadata API is the objective, the public application is the
vector, and a rule that carries only the credential-access mapping loses the tactic under which
this alert actually arrives. Both IDs verified live 2026-08-29:
T1552.005 = *Unsecured Credentials: Cloud Instance Metadata API*, T1190 = *Exploit Public-Facing
Application*.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction
(workflow step 0) deliberately, for the reason given in the authoring brief: the originals are
packaged in a proprietary format whose scaffolding identifies the source on sight while bearing on
nothing about whether the rules are correct. What is retained is the complete detection logic:
name, priority, type, MITRE label, the Lucene query verbatim, threshold, window and group-by.
Generated with the shared extractor, not by hand.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation only.

The four rules also appear in `../../ec2.credential-access.imds-credential-theft/_source/`,
captured there alongside a fifth flow-log alert because that playbook models the technique across
two telemetry families. The extracts are the same four alerts and regenerate identically; neither
copy is derived from the other.

**Merge test — applied, not assumed. Four source rules, one use case.** The four rules match the
same Core Rule Set signature family across the four places a request can carry a payload — URI path,
query arguments, body and cookie. They are one technique observed through four request components,
they share a response entirely, and an actor probing for IMDS through a proxy will commonly trip
more than one of them in a single request. Splitting them would produce four playbooks with one
identical procedure and would break the ability to see a single request that matched several
components.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.
