# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Threshold rule over a query string |
| Scope captured | One alerting rule: NS Record Created or Updated |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.
Shipped `references:` cite public AWS and MITRE documentation only.

The source rule is one threshold query and is fully readable, so every row of the
`Issue | Impact | Correction` table in `../PLAYBOOK.md` §2 is auditable against the artifact.

**MITRE:** mapped to **T1584.001 — Compromise Infrastructure: Domains**, verified live, with
**T1584.002 — Compromise Infrastructure: DNS Server** as secondary for the delegated-away case.

The
replacement is wrong too. `T1685` is Defence Impairment; creating a delegation impairs no
defence and clears no log — it hands a subtree to someone else while leaving every existing
record, every service and every log intact. `T1584.001` covers it in words: "subdomain
hijacking", and "domain shadowing by creating malicious subdomains under their control while
keeping any existing DNS records. As service will not be disrupted, the malicious subdomains may
go unnoticed for long periods of time."

The directory keeps its `stealth.` prefix because the prefix is a stable identifier derived from
the source rule, not a claim about the corrected mapping — the same convention as
`../../route53.stealth.dns-zone-deleted/`, which is mapped to `T1485`. The reason two IDs appear at
all is settled once in `../../_ground-truth/route53.md` §10: every DNS- and domain-shaped ATT&CK
technique is modelled adversary-centrically on the **PRE** platform, so none of them returns
under `platform=IaaS`.

**Scope, and what is deliberately not here.** The source pack ships NS **deletion** as a separate
alerting rule and it stays a separate use case. This playbook is the create-or-update case only.
Nothing has been aggregated.

**Tier:** 1, on criterion 4 of `07-TIERS.md` — *the evidence is destroyed by the remediation*.

Service ground truth for every `route53.*` playbook is in `../../_ground-truth/route53.md`, audited
once on 2026-08-29. NS semantics are §12; the dangling-delegation window AWS documents in its own
words is §8b; `ChangeResourceRecordSets` field shapes are §4 and §4a; regionality is §1;
query-logging limits are §13.
