# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | New-value rule over a threshold building block |
| Scope captured | Two rules, one use case: Unfamiliar IAM User Listed Secrets, and its Secrets Listed building block |
| Retrieved | 2026-08-30 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

No source, vendor, product, repository or package is named in any file in this project.

## Merge test — case 2

*Unfamiliar IAM User Listed Secrets* is a `logs_new_value` alert with **no query of its own**: it is
a correlation over the *Secrets Listed* building block, adding no new observable. That is case 2 of
`07-TIERS.md` exactly — "a correlation rule that is purely the composition of building blocks you are
already shipping" — so the pair is one use case and the correlation becomes a document inside this
playbook's Sigma rather than a playbook of its own.

**A separate rule is held elsewhere.** *Multiple Failed Access Attempts* is a threshold rule on a
different observable — any Secrets Manager call returning `AccessDenied` — with a different
response. Under `07-TIERS.md` that is neither permitted merge case, and the doctrine is explicit
that sharing a service is not grounds. It lives in
`../../secretsmanager.discovery.access-repeatedly-denied/` and is cross-referenced.

One correction from that episode is kept because it stands on its own: the building block excludes
errors, so a **denied** `ListSecrets` is not a listing event — a principal that asked for the whole
inventory and was refused produces nothing here. A document with no threshold closes that.

## What the source rules get wrong

**`T1552 — Unsecured Credentials`.** Secrets Manager is a credential store being used as designed;
nothing about it is unsecured. `T1526 — Cloud Service Discovery` is the enumeration, and
`T1555.006 — Cloud Secrets Management Stores` is the objective it serves. `T1580 — Cloud
Infrastructure Discovery` was considered and set aside: it is scoped to IaaS compute and storage.
All verified live 2026-08-31.

**Listing treated as harmless because no value is returned.** `ListSecrets` returns `Name`,
`Description`, `Tags`, `RotationEnabled` and `LastAccessedDate` — which systems exist, which secrets
are live, and which will never rotate. That is the reconnaissance product, and it is why listing is
rated here rather than logged. See `../../_ground-truth/secretsmanager.md` §3.

**`ListSecrets` is not the only enumeration path, and the source covers only that one.** A principal
holding secret ARNs but not `ListSecrets` enumerates with `DescribeSecret`, one secret at a time,
returning the same metadata. Nothing in the source set sees it. Covered here by a cardinality
correlation.

**Boundary with the neighbouring playbook.** The same building block also appears in
`../../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/`, which owns
the list-then-retrieve sequence and `GetSecretValue` volume. This playbook owns enumeration that has
**not** produced a retrieval. Neither restates the other's response.

**Tier:** 1, on criterion 3 of `07-TIERS.md` — *the blast radius is not in the event*.

Service ground truth for every `secretsmanager.*` playbook is in `../../_ground-truth/secretsmanager.md`,
audited 2026-08-30. §3 covers what listing discloses.
