# Detection Note — T1526 (Cloud Service Discovery)

**Signal:** a principal being refused by Secrets Manager, repeatedly.

## `AccessDenied` is not brute force

The source rule maps `T1110` under Initial Access. Brute force is guessing credentials. An
`AccessDenied` from Secrets Manager is returned to a principal whose credential **authenticated
successfully** and whose authorization failed — so the technique does not apply, and Initial Access
is wrong for the same reason: the actor is already inside.

`T1526 — Cloud Service Discovery`, verified live 2026-08-31.

## Grouping by role name cannot see the actor

The rule groups by `userIdentity.sessionContext.sessionIssuer.userName`, which holds the **role**
name. Every concurrent session of that role shares it. Twenty sessions with one denial each are
indistinguishable from one session with twenty, and the alert names the role rather than the actor.

The listing rule in the neighbouring playbook groups by `userIdentity.arn`, which does carry the
session. Same service, two keys, no stated reason. Regrouped on the session here.

## Twenty in five minutes is a loop, not a person

Four denials a minute sustained is a workload retrying. Ten in fifteen minutes catches that **and** a
patient actor walking the inventory by hand.

## `AccessDenied` exactly is too narrow

A call blocked by an SCP or a permissions boundary can surface with a different code —
`AccessDeniedException` rather than `AccessDenied` — so an exact-match filter under-counts in any
account that uses them. The base rule here matches on the prefix and also carries
`UnauthorizedOperation`.

## The discriminator the source rule has no way to express

| Shape | Meaning |
|---|---|
| Many denials, **one** secret id | A workload missing a grant. The dominant false positive. |
| Many denials, **many distinct** secret ids | An inventory being probed. The finding. |

`DeniedSecrets` separates them in a single field, and it dismisses the common case without touching
IAM. It is the reason this playbook ships two correlations rather than one.

## Response levers

**One question sets severity: did anything succeed?** A denial burst alongside a successful
`GetSecretValue` is a principal that found what it could reach. The KQL surfaces both in the same
row.

**MITRE:** `T1526 — Cloud Service Discovery` (verified live 2026-08-31). The source's `T1110 —
Brute Force` under Initial Access does not apply: the credential authenticated and only the
authorization failed, so the actor is already inside. `T1580 — Cloud Infrastructure Discovery`
was considered and set aside as scoped to IaaS compute and storage.

**Every Secrets Manager call is a management event.** The denial data is complete and free, so an
empty result genuinely means it did not happen.

**A denial burst is usually benign.** Say so in the finding. The value of this detection is the
cardinality field, not the count.

**GuardDuty:** `Discovery:IAMUser/AnomalousBehavior` can surface an unusual burst, but it is
behavioural and not guaranteed. No finding type covers Secrets Manager denials specifically.

**Adjacent:** successful listing of the inventory is
`../../secretsmanager.discovery.secrets-enumerated/`; retrieval volume is
`../../secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/`.

**Files here:**
- `sigma_t1526.yml` — three documents: `secretsmanager_call_denied` as the informational base rule
  matching on the error-code prefix, a ten-in-fifteen-minutes correlation grouped on the session
  (high), and a five-distinct-secrets correlation that separates probing from a retry loop (high).
- `kql_t1526.kql` — reports denials with their per-secret and per-action cardinality, flags the
  retry-loop shape, and rates a burst alongside a successful retrieval above everything else.

Full response procedure is in `../PLAYBOOK.md`.
