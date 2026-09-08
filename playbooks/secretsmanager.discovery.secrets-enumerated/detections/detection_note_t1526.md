# Detection Note — T1526 (Cloud Service Discovery)

**Signal:** a principal reading the Secrets Manager inventory — by listing it, or by walking it one
ARN at a time.

## Listing is not harmless because no value is returned

`ListSecrets` returns `Name`, `Description`, `Tags`, `RotationEnabled` and `LastAccessedDate` —
which systems exist, which secrets are live, and which will never rotate. That is the reconnaissance
product. See `../../_ground-truth/secretsmanager.md` §3.

## A denied listing produces nothing

The building block ends `NOT _exists_:errorCode`, so a **refused** `ListSecrets` is not a listing
event. A principal that asked for the whole inventory and was told no leaves no trace in it.

`secretsmanager_secrets_listed_denied` closes that with no threshold at all — there is no volume at
which "asked for everything and was refused" becomes more interesting.

## `ListSecrets` is not the only path

A principal holding secret ARNs but not `ListSecrets` enumerates with **`DescribeSecret`**, one call
at a time, and the response carries the same metadata. Nothing in the source set sees it.

The cardinality correlation here — ten distinct secrets described in fifteen minutes — covers it,
and the KQL flags the shape explicitly: many describes with **zero** listings is a principal that
either lacks the permission or is avoiding the call the rules watch.

## Response levers

**One question decides the severity: did any `GetSecretValue` succeed?** The KQL surfaces retrievals
alongside the enumeration for exactly that reason, even though retrieval volume is owned by
`../../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/`.

**Every Secrets Manager call is a management event.** No data events, no cost, no configuration —
so an empty result here genuinely means it did not happen, unlike the S3 and DynamoDB equivalents.

**CloudTrail records that the inventory was listed, never what came back.** What the actor learned
has to be reconstructed from your own side, and the metadata that makes it valuable is not in the log.

**MITRE:** `T1526 — Cloud Service Discovery` (verified live 2026-08-31); the objective is
`T1555.006 — Cloud Secrets Management Stores`. The source's `T1552 — Unsecured Credentials` does not
apply: a credential store used as designed is not an unsecured credential. `T1580 — Cloud
Infrastructure Discovery` was considered and set aside as scoped to IaaS compute and storage.

**GuardDuty:** no finding type covers Secrets Manager enumeration.
`Discovery:IAMUser/AnomalousBehavior` can surface an unusual `ListSecrets`, but it is behavioural and
not guaranteed.

**Adjacent:** denial bursts across the service are
`../../secretsmanager.discovery.access-repeatedly-denied/`.

**Files here:**
- `sigma_t1526.yml` — four documents: listing by a principal outside the allowlist (medium), denied
  listing with no threshold (medium), `secretsmanager_secret_described` as the informational base
  rule, and a ten-distinct-secrets `DescribeSecret` correlation (medium).
- `kql_t1526.kql` — reports both enumeration paths, flags a principal that walks the inventory while
  never calling `ListSecrets`, and surfaces whether enumeration became retrieval.

Full response procedure is in `../PLAYBOOK.md`.
