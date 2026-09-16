# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rules plus a FLOW composition |
| Scope captured | One alerting rule and both of its building blocks |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS, MITRE and RFC/CA-Browser-Forum documentation only.

## Both building blocks resolved — and they change the verdict

Unlike the other flow rules in this project, this one's stages **could** be recovered: stage 26
is `DisableDomainTransferLock`, stage 27 is `TransferDomainToAnotherAwsAccount`, joined within
one hour and grouped by `requestParameters.domainName`. All three are in `original_rules.yml`,
so every row of the `Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable
against the artifact.

That resolution is what makes the central finding statable rather than speculative. The rule is
named "Domain Transfer Lock Disabled Followed by Domain Transfer", and the only "domain
transfer" it can observe is `TransferDomainToAnotherAwsAccount` — the **account-to-account move
inside AWS**, operation type `INTERNAL_TRANSFER_OUT_DOMAIN`. The registrar transfer-out, which
takes the domain out of AWS permanently and cannot be undone by any AWS API, is executed at the
**gaining registrar** and produces no CloudTrail event in this account at all. The rule therefore
cannot fire on the scenario its own title describes.

**MITRE:** mapped to **T1584.001 — Compromise Infrastructure: Domains**, verified live. The
source carries bare `T1584`, which is correct but under-specified; `.001` names registration
hijacking exactly and cites AWS Route 53 by name. `T1078` is carried as secondary — the
registrar API is reached with valid credentials, and that is the IaaS-platform half of the
mapping. The two-ID convention and the reason for it (every DNS- and domain-shaped ATT&CK
technique is modelled adversary-centrically on the **PRE** platform, so none of them returns
under `platform=IaaS`) is settled once in `../../_ground-truth/route53.md` §10 and not re-argued
here.

**Merge test:** the two building blocks are folded into this playbook rather than shipped as
separate use cases, because a building block is not an alerting rule — it exists only to be
referenced. The two *alerting* rules in the source pack that touch the registrar are this one
and nothing else, so no aggregation of distinct use cases has occurred.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `route53.*` playbook is in `../../_ground-truth/route53.md`, audited
once on 2026-08-29. The transfer chain is §7 and §7a; regionality is §1; the two event sources
are §2; the ATT&CK mapping table is §10; what could not be verified is §15.
