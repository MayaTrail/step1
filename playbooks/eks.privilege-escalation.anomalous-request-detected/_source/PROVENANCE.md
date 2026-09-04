# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query string over Kubernetes audit events |
| Scope captured | One alerting rule: Anomalous Request Detected |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public MITRE, AWS and Kubernetes documentation only.

**MITRE:** mapped to **T1609 — Container Administration Command**, which names execution
through the container administration service exactly. The source rule carries `t1078`
(Valid Accounts), which describes the *access* rather than the *act* — a mapping-precision
correction. Verified live with `tools/attack_currency_check.py`.

**Naming:** the directory keeps the catalogue slug `anomalous-request-detected` for
traceability to the source rule, but the use case is command execution in a running pod.
The source rule's title describes an anomaly-detection intent its query does not implement:
it matches two fixed strings, not an anomaly.

**Merge test:** not applicable — one source rule, one use case. The sibling
`User Exec Into a Pod` in the same source pack is a separate catalogue entry covering the
same observable with a different query; when it is authored, merge test 1 should be assessed
against this playbook rather than a second one written.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `eks.*` playbook is in `../../_ground-truth/eks.md`, audited once
on 2026-08-29. Subresource semantics are §4; the identity systems and the credential
endpoints are §5.
