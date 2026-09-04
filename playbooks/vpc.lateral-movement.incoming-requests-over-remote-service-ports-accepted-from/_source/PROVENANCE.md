# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: Incoming Requests Over Remote Service Ports Accepted From Malicious IP |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project. The
extract's reputation field carried a provider name as a path segment; it is rendered
`<provider>` by `tools/deid_extract.py`, which learned that shape from this rule.

The source rule is one threshold query and is fully readable, so every row of the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**The defect worth naming here is an inverted priority.** The rule will not fire unless the source
address carries a high-confidence reputation score. That gate sits in front of the only fact that
matters — a remote-administration service is reachable from the public internet — so the rule is
silent for every address nobody has reported yet, which includes every address on its first day
and every address an attacker rents fresh for the purpose. The gate also lives in an enrichment
pipeline rather than in the flow log, so if that pipeline is absent or its schema changes the rule
reports clean forever with nothing to indicate why.

The corrected set inverts it. The accepted connection is the rule, at high, with no enrichment
required; the reputation hit is a separate rule at critical, layered on top, which raises urgency
when present and proves nothing when absent.

**MITRE:** `T1021 — Remote Services`, the source's mapping, kept and verified live 2026-08-30,
with `T1133 — External Remote Services` added because the observable is an externally-facing
remote-access service being reached rather than movement between internal hosts. `T1595 — Active
Scanning` is carried by the refused-connection rules.

**Merge test:** not applicable — one source rule, one use case. The port-scan-shaped correlation
here overlaps in form with the one in
`../../vpc.initial-access.critical-database-exposure-to-public-internet/`, and the two are kept
separate because the ports, the response and the blast radius differ — an exposed database is a
data incident, an exposed SSH port is a host-access incident.

**Tier:** 1, on criterion 5 of `07-TIERS.md` — *the detection has a structural blind spot worth a page of honesty*.

Service ground truth for every `vpc.*` playbook is in `../../_ground-truth/vpc.md`, audited on
2026-08-30. Field versions are §2, the `srcaddr` versus `pkt-srcaddr` distinction is §3, `action`
and `log-status` semantics are §5.
