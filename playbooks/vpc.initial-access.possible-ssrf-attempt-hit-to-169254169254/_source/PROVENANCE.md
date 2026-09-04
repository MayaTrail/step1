# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Possible SSRF Attempt (Hit to 169.254.169.254) |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

## The finding that reshaped this playbook

The source rule is `destination_ip:"169.254.169.254" AND action:"ACCEPT"` against VPC Flow Logs.
**It cannot fire.** AWS's *Flow log limitations* page lists, among the traffic flow logs do not
capture:

> Traffic to and from `169.254.169.254` for instance metadata.

Verified against AWS documentation on 2026-08-30 and quoted in `../../_ground-truth/vpc.md` §1. There
is no custom format, aggregation interval or field selection that makes the record appear. A rule
that cannot fire is worse than a missing rule: it reports clean in perpetuity and makes a coverage
audit look satisfied.

**So the playbook is not a corrected version of the source rule** — a correction is not available.
It is built on the observation that *only the link-local metadata address is excluded*. Every
other destination the same SSRF primitive reaches is logged, and an application server opening
connections it has no client library for is the same attack producing a signal AWS does record.

**Scope, and the three disjoint views.** The IMDS half of this technique is already covered and is
deliberately **not** restated here: `../../ec2.credential-access.imds-credential-theft/` detects
the resulting role session being used away from the instance, in CloudTrail;
`../../waf.credential-access.crs-ssrf-ec2-metadata/` detects the inbound request carrying the
metadata signature, in web ACL logs. This playbook is the network view — the internal probing.
The three do not overlap, and each names the other two rather than duplicating them.

**MITRE:** `T1190 — Exploit Public-Facing Application` primary, matching the source's mapping,
which is correct: the SSRF is the exploitation. `T1046 — Network Service Discovery` is carried by
the rules that fire, because internal enumeration is what the telemetry actually shows, and
`T1552.005 — Unsecured Credentials: Cloud Instance Metadata API` names the objective. All three
verified live 2026-08-30.

**Merge test:** not applicable — one source rule, one use case.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `vpc.*` playbook is in `../../_ground-truth/vpc.md`, audited on
2026-08-30 against the AWS VPC User Guide. The not-logged list is §1; version-2-versus-custom
format is §2; the `srcaddr` vs `pkt-srcaddr` distinction is §3; timing is §6.
