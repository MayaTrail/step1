# Detection Note — T1190 (Known-Bad IP with Allowed Web Attack)

**Signal:** one request carrying both an AWS IP-reputation label and a web-attack label,
served to the application.

**The composite it asks for is nearly unreachable at AWS managed defaults, and that is a
fact about evaluation order rather than about traffic.**

## Why the source rule almost never fires

WAF rules run in priority order. A **terminating** action ends evaluation immediately —
nothing after it runs, and nothing after it labels. Labels are visible only to rules that
run *after* the rule which added them. Both of the source rule's signals therefore have to
land on **one request in one evaluation**.

| Reputation rule | Default action | Consequence |
|---|---|---|
| `AWSManagedIPReputationList` | **Block** | terminates; attack groups never run; **no attack label** |
| `AWSManagedReconnaissanceList` | **Block** | same |
| `AWSManagedIPDDoSList` | **Count** | labels, evaluation continues — the only one that can coexist |

So with the reputation group placed first, which is the usual and recommended placement, a
match blocks and stops. The CRS, SQLi and known-bad-inputs groups never execute, and a rule
requiring both labels cannot fire. **That is the control working perfectly.**

Placed the other way round, an attack that the attack group blocks terminates first and the
reputation label is never added. Either ordering suppresses the composite.

**Net: the rule covers one of its three reputation lists, and only when the attack rule that
also matched did not terminate.** Its silence means "evaluation order", not "no attacker" —
and nothing in the alert says so.

## What that changes about the verdict

Because `AWSManagedIPDDoSList` is Count by design, a request labelled by it *and* by an
attack rule *and* allowed is the **expected** shape, not an anomaly. The finding there is
the attack, and the address is context.

The genuinely alarming case is the same combination involving one of the **Block** lists.
That can only happen if the reputation group was overridden to Count — a real and
defensible configuration (label-only reputation, block decided later) which the source rule
silently depends on, and which means the protection is off.

The shipped rules split those two verdicts. They also keep the case the source rule discards
entirely: a reputation-listed address that was **blocked** carries no attack label, so a
both-labels rule can never see it — yet it is the most common real observation and, at
volume from one address, the targeting signal that precedes everything else.

## The address is the origin, not necessarily the client

The reputation group evaluates the **web request origin** address. Behind a proxy, a CDN in
front of your CloudFront distribution, or a second load balancer, that is the intermediary —
so a listed address may be your own edge and the traffic may be someone else's. Establish
the true client from `X-Forwarded-For` inside `httpRequest.headers` before acting on an IP,
and remember that header is attacker-controllable.

**A customer `IPSet` produces no label at all** unless the customer's own rule adds one with
`RuleLabels`. A label-matching rule cannot see a customer IP set by default — so "known-bad"
here means specifically the AWS managed reputation group, not your own blocklist.

## Field shapes that silently return nothing

- **`labels` is an array of single-key objects** — `[{"name": "awswaf:managed:aws:amazon-ip-list:AWSManagedIPReputationList"}]`.
  The path is `labels[].name`. A flat match on `labels` returns empty.
- **There is no `httpRequest.host`.** The Host value lives inside the `headers[]` array as a
  `{name, value}` pair and has to be picked out of it.
- **Label matching is case-sensitive and the label is not derivable from the rule name.**
  Match the component-independent stem (`:SQLi_`, `:EC2MetaDataSSRF_`) and read the
  component off the matched label. The same rule group ships `SQLi_URIPath` and
  `SQLiExtendedPatterns_UriPath`, so any casing transform returns zero for one of them.
- `webaclId` holds the web ACL **ARN**, despite the name.

## Response levers

**The rule group carries no versioning and no update notifications.** You cannot pin it,
and you will not be told when its contents change — so an address that was listed yesterday
may not be today, and vice versa. Treat a reputation hit as corroboration, never as the
finding on its own.

**Adding your own `IPSet` block is the fast containment**, but it is an address-based
control against an attacker who can change address. Use it to buy time, and fix the
application defect the attack label named.

## What is not recoverable

The request body is never written to the WAF log. If the attack label came from a body rule,
the payload is not here and must come from the application. And for any window in which the
web ACL had **no logging configuration**, there is no request record at all and never will
be — see `../../waf.stealth.no-logs-from-aws-waf/`.

**MITRE:** `T1190 — Exploit Public-Facing Application`, which is the source's own mapping and is correct. Verified live 2026-08-30.

**GuardDuty:** no finding type covers AWS WAF. GuardDuty has no WAF resource type at all, so nothing here is duplicated by it — these rules are the only coverage for this technique.

**Files here:**
- `sigma_t1190.yml` — three documents: the reachable composite (`high`), the
  blocked-at-reputation base rule (`low`), and a sustained-targeting correlation over
  blocked requests (`medium`).
- `kql_t1190.kql` — both signals in one query, with the verdict distinguishing the
  Count-by-design DDoS list from an overridden Block list.

Full response procedure is in `../PLAYBOOK.md`.
