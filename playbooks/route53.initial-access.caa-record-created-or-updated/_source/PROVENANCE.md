# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: CAA Record Created or Updated |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS, MITRE, IETF and CA/Browser Forum documentation only.

The source rule is fully readable — a single threshold query, not a flow — so every row of the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**MITRE:** mapped to **T1685 — Disable or Modify Tools** (Defense Impairment, TA0112), verified
live, with **T1588.004 — Obtain Capabilities: Digital Certificates** as the adversary objective
and **T1608.003 — Stage Capabilities: Install Digital Certificate** as the next stage.

The source carries `T1596`, which is **wrong**: `T1596` is *Search Open Technical Databases*, a
Reconnaissance technique about an adversary reading public DNS data. Modifying your own CAA
policy is not reconnaissance in any direction. `T1685` is a stretch — a CAA record is not a
"tool" — and it is chosen deliberately anyway, because its own description extends to
"disrupting preventative, detection, and response mechanisms across host, network, and cloud
environments", CAA is exactly a preventative mechanism, and it is the only live technique in
this space carrying the IaaS platform. The reason a second, PRE-platform ID is needed at all is
settled once in `../../_ground-truth/route53.md` §10 and not re-argued: every DNS-, domain- and
certificate-shaped ATT&CK technique is modelled adversary-centrically, so none of them returns
under `platform=IaaS`.

**Scope, and what is deliberately not here.** The source pack ships CAA **deletion** as a
separate alerting rule, and it stays a separate use case. This playbook is the
create-or-update case only — which is the subtler one, because RFC 8659 makes authorisations
additive: adding one `issue` value beside a deny-all opens issuance to that CA while the record
still exists, so a rule keyed on absence never fires. Nothing has been aggregated.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

This was drafted as Tier 2 and grew past the band while being written, which is the honest
reason it is labelled Tier 1 rather than trimmed: the material that pushed it over — additive
authorisations, tree-climbing, the CA/Browser Forum issuance window — is what makes the playbook
correct rather than merely complete. Removing it would leave a responder restoring a DNS record
and closing the incident, which is the exact failure the playbook exists to prevent.

Service ground truth for every `route53.*` playbook is in `../../_ground-truth/route53.md`, audited
once on 2026-08-29. CAA semantics and the issuance window are §11; the
`ChangeResourceRecordSets` field shapes and their traps are §4 and §4a; regionality is §1;
query-logging limits are §13; the ATT&CK table is §10.
