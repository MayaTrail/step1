# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: ALB Not Using Secure Listener |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

The source rule is one threshold query and is fully readable, so every row of the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**The defect worth naming is that the rule cannot distinguish the recommended configuration from
the defect.** An HTTP listener whose only action is a redirect to HTTPS is the pattern AWS
recommends for port 80; an HTTP listener that forwards to a target group is the exposure. Both
produce `type: http` access log entries, and only `actions_executed` separates them — a field the
source rule does not read. In a correctly configured estate the rule therefore fires continuously
on redirects, and in an exposed one it says the same thing.

**Its threshold inverts the risk.** Ninety-nine matches in an hour is a volume test applied to a
configuration fact. One forwarded plaintext request proves the listener exists and serves; a
low-traffic internal admin endpoint — the most likely thing to be left on port 80, and the most
valuable to intercept — never reaches ninety-nine and never alerts.

**And restricting to `elb_status_code` 200–299 misses the credential.** A plaintext request that
received a 401 still carried its `Authorization` header over the wire before being rejected. The
interception has already happened by the time the status code exists, so response status has no
bearing on exposure and is not filtered on in the corrected rules.

Two smaller corrections: `ws` is a plaintext type alongside `http` and was unmatched, so every
unencrypted WebSocket was invisible; and the geo-enrichment used to mean "external" is replaced by
reading the client address directly, with internal sources kept as a lower-severity finding rather
than excluded — a credential on an internal network is still a credential somebody else can read.

**MITRE:** `T1557 — Adversary-in-the-Middle`, the source's mapping, kept and verified live
2026-08-30, with `T1040 — Network Sniffing` added because passive capture of an unencrypted request
requires no interposition at all and is the more likely of the two.

**Merge test:** the deprecated-TLS rule is shipped in this file rather than as its own use case
because it answers the same question — is this traffic actually protected — and the answer has
three states rather than two. No separate source rule covers it, so nothing has been aggregated.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `alb.*` playbook is in `../../_ground-truth/alb.md`, audited on
2026-08-30. The `type` field values are §3; `actions_executed` is §7; the best-effort statement is
§1; the control plane is §9.
