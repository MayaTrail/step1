# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Multiple Failed Authentication |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

The source rule is one threshold query and is fully readable, so every row of the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**The defect worth naming is that it counts an outage as an attack.** `NOT error_reason:"-"`
matches every non-empty error reason, and AWS splits those into two families with two different
CloudWatch metrics: `ELBAuthFailure` for request-side problems — a bad cookie, an invalid grant, a
tampered token — and `ELBAuthError` for the identity provider being unreachable. During an IdP
outage every client produces the second family at once, so a threshold of 14 in five minutes fires
for every source address simultaneously. The security on-call is paged for an identity team's
availability incident, at scale, and the rule is muted shortly afterwards.

**It also cannot see the strongest signal in the field it reads.** JWT validation failures are
recorded in the same `error_reason` field but come from a `jwt-validation` action, which the rule's
`actions_executed:"authenticate"` filter excludes. `JWTSignatureValidationError` means a token was
presented whose signature does not verify — forged or wrongly signed — and there is no benign
explanation for it at volume.

**And the grouping key may not be the client.** AWS: *"If there is a proxy in front of the load
balancer, this field contains the IP address of the proxy."* ALB access logs carry no
`X-Forwarded-For` field, so behind CloudFront the whole internet groups onto a few edge addresses.
That is stated in the shipped rules rather than silently mis-grouped, with the note that the
correct detection point in that topology is the CloudFront log or the web ACL.

**MITRE:** `T1110 — Brute Force`, the source's mapping, kept for the volume rules and verified live
2026-08-30. `T1212 — Exploitation for Credential Access` is added for the state-parameter and JWT
rules, which are not guessing attacks: a forged token signature and a failed OAuth CSRF binding are
attempts to defeat the authentication mechanism rather than to exhaust it.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `alb.*` playbook is in `../../_ground-truth/alb.md`, audited on
2026-08-30. The error-reason families are §6; the proxy caveat on the client field is §3; the
best-effort statement is §1.
