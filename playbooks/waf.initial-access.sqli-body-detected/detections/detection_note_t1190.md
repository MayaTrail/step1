# Detection Note — T1190 (SQL Injection in Request Body)

**Signal:** AWS WAF matched an SQL-injection pattern in a request body — and the request
was still served to the application.

**The alert does not mean what its title means.** Every rule in
`AWSManagedRulesSQLiRuleSet` has a default action of **Block**. So an `ALLOW` sitting
alongside an `SQLi_Body` label is not "an injection got through the WAF" — it is *"the
WAF was configured not to stop it."* Only two configurations produce it: the rule group
was overridden to Count, or the specific rule was excluded. **The finding is that the
protection is off**, and that is a different conversation with a different owner than a
web-application incident.

## What the original rule got wrong

**The `ALLOW` gate inverts the alert.** Gating on `action:"ALLOW"` means the rule is
silent in every web ACL running the SQLi group at its defaults — which is every correctly
configured one. And because a blocked attempt raises nothing at all, the attacker is
invisible *precisely when the control is working*. There is no configuration in which this
rule tells you that someone is attacking you; it only ever tells you the shield is down.

The correction is the same one this corpus has now applied to every WAF rule: **the
terminating action is a verdict axis, never a filter.** Match the label, emit the action,
and let `ALLOW` be P0 while `BLOCK` becomes a volume signal.

**The volume threshold compounds it.** Four allowed injections in five minutes is a tuning
floor for a noisy signal. This signal means the control is disabled; one is an incident.

## CAPTCHA and Challenge did not reach the application

AWS: *"The CAPTCHA and Challenge actions are terminating when the web request doesn't
contain a valid token."* A CAPTCHA-terminated request has `action: "CAPTCHA"`,
`responseCodeSent: 405`, and `captchaResponse.failureReason: "TOKEN_MISSING"` — the
backend never saw it. Treat those with `BLOCK`, not with `ALLOW`.

The inverse case matters too: a CAPTCHA rule matching a request that *does* carry a valid
token yields a top-level `action: "ALLOW"` with the CAPTCHA match recorded under
`nonTerminatingMatchingRules[]`. That request **did** reach the application.

## The body limit is an evasion path the rule structurally cannot see

| Component | Limit | Adjustable |
|---|---|---|
| Body / JSON body — **ALB, AppSync** | **8 KB, fixed** | **No** |
| Body / JSON body — CloudFront, API Gateway, Cognito, App Runner, Verified Access | 16 KB default | Yes, to 64 KB |

Every AWS managed body rule uses oversize handling **`Continue`** — inspect what fits,
then carry on. And AWS is explicit about what happens next: *"When AWS WAF allows a web
request to proceed to your protected resource, the entire web request is sent, including
any contents that are outside of the count and size limits that AWS WAF was able to
inspect."*

So on an ALB-fronted application, 8 KB of filler in front of the payload defeats every
body rule in the web ACL, and the whole body still reaches the backend. The log shows it:
`oversizeFields` contains `REQUEST_BODY` while no body rule matched. That is why an
`informational` rule on that condition ships alongside — not as an alert, but as the
context that explains an absence.

**One compensating control is worth checking first:** the Core rule set ships
`SizeRestrictions_BODY`, which blocks bodies over 8,192 bytes. If it is present and not
overridden, the padding trick is blocked outright and the body rules are sound.

**Scope the caveat to body rules only.** `SQLi_URIPath`, `_QueryArguments` and `_Cookie`
do not inspect the body and are unaffected.

## Label casing is not derivable — read it, do not transform it

The label is `awswaf:managed:aws:sql-database:SQLi_Body`. Matching is **case-sensitive**,
and the managed rule *name* and the label it emits are related by no mechanical transform.
The same rule group ships both of these:

```
SQLi_URIPATH                 ->  SQLi_URIPath
SQLiExtendedPatterns_URIPATH ->  SQLiExtendedPatterns_UriPath
```

`URIPath` and `UriPath`, in one group. Any title-case or upper-case transform returns zero
for one of them, and anchoring on the substring `_URIPath` misses `_UriPath`. Match the
component-independent stem and read the component off the matched label.

## Absence is a configuration answer before it is a traffic answer

`AWSManagedRulesSQLiRuleSet` is **use-case specific and not part of a baseline
deployment**. If it is not associated with the web ACL, every SQLi label is absent and
every rule here returns nothing — because the group is missing, not because nobody
attacked. Confirm the group is associated before reading silence as clean. The same
applies one level up: **WAF traffic logging is off by default** and is enabled per web ACL
by `wafv2:PutLoggingConfiguration`. See `../../waf.stealth.no-logs-from-aws-waf/`.

## What is not recoverable

**The body is never in the log.** WAF records headers and the query string; it does not
record the request body. The payload behind a body match is not in WAF and cannot be
retrieved from it — it must come from the application. `matchedData` helps only partly:
match details are populated **only for SQL-injection and XSS match statements**, so the
`SQLi_*` rules do populate it (sensitivity `Low`) while the regex-based
`SQLiExtendedPatterns_*` rules produce an empty array.

## Response levers

**MITRE:** `T1190 — Exploit Public-Facing Application`, which is the source's own mapping and is correct. Verified live 2026-08-30.

**GuardDuty:** no finding type covers AWS WAF. GuardDuty has no WAF resource type at all, so nothing here is duplicated by it — these rules are the only coverage for this technique.

**Files here:**
- `sigma_t1190.yml` — four documents: SQLi body allowed (`high`), the blocked base rule
  (`low`), a sustained-probing correlation on blocked attempts (`medium`), and the
  oversize-body context rule (`informational`).
- `kql_t1190.kql` — both verdict streams in one query, with the label-array and
  missing-`host` handling the log schema requires.

Full response procedure is in `../PLAYBOOK.md`.
