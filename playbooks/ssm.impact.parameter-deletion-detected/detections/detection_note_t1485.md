# Detection Note — T1485 (Data Destruction)

**Signal:** `ssm:DeleteParameter` or `ssm:DeleteParameters` succeeding for a
principal that does not own the configuration lifecycle.

**This one is terminal, and AWS says so in one sentence.** *"Deleting a parameter
removes all versions of it. Once deleted, the parameter and its versions can't be
restored."* There is no recovery window and no soft delete — the contrast with
Secrets Manager, which holds a deleted secret for 7 to 30 days by default, is the
thing to hold in mind, because a responder carrying that expectation over will
spend the first ten minutes looking for a restore that does not exist. By the time
this alert reaches a human, the only questions left are what, how much, and where
the value can be sourced from outside AWS.

**What the original rule got wrong.** It is an immediate-type alert on
`deleteparameters OR deleteparameter` with no threshold, no window, no group-by
and no success filter. Three consequences, in order of how quickly they bite:

1. **It fires on every teardown.** An infrastructure-as-code `destroy` removes the
   environment's parameters, so the alert fires in bulk on planned work and is
   muted inside a week — after which the real deletion is silent.
2. **The empty group-by makes a mass deletion arrive as N alerts, not one
   incident.** The responder reconstructs the scope by reading a page of
   notifications instead of one aggregated finding.
3. **It counts events, and events are not parameters.** `DeleteParameters` takes
   up to **ten names per call**, so five events can be fifty destroyed parameters.

The source rule's **MITRE mapping is correct** — T1485 (*Data Destruction*) under
Impact (TA0040) is exactly right, and this is the one alert in the Systems Manager
set whose label needs no dispute. The priority, P3, is the disagreement: a
destruction with no possible restore is not a next-business-day item.

## "No `errorCode`" does not mean "everything named was destroyed"

`DeleteParameters` has exactly **one** documented error, `InternalServerError`.
Names that do not exist come back in the 200-response `InvalidParameters` array.
So a clean-looking event naming ten parameters may have destroyed ten, or one, or
none, and the alert cannot tell you which.

`responseElements.deletedParameters` would settle it, and AWS does **not** document
whether CloudTrail records `responseElements` for this call. Read it if it is
there; do not build the scope on it. The reliable reconciliation is against the
live inventory:

```
aws ssm describe-parameters \
  --parameter-filters "Key=Path,Option=Recursive,Values=<path>" \
  --query 'Parameters[].Name'
```

A requested name that is now absent was destroyed. A requested name still present
was not — either it was in `InvalidParameters`, or somebody has recreated it since,
which is a separate and equally interesting finding.

## Two deletions this rule can never see

**A delete aimed at a name that does not exist emits nothing.** AWS: *"For the
`DeleteParameter` and `GetParameter` actions, if the specified parameter doesn't
exist, the `ParameterNotFound` exception is not recorded in AWS CloudTrail event
logs."* So a principal probing the namespace through the delete API — trying names
to see which ones it can remove — leaves no trace for the misses at all. There is
no error-based detection for that path.

**A parameter removed by an expiration policy has no deleter.** `PutParameter`
accepts a `Policies` array, and AWS documents the `Expiration` type as deleting the
parameter when its timestamp is reached. Parameter Store performs that deletion
itself, so no principal appears in any event. The destruction is armed at write
time and is only visible there — see
`../../ssm.discovery.excessive-parameter-creation-detected/`, whose expiration-policy
rule is the only warning this class of deletion ever produces.

## Read-then-destroy is the pattern worth correlating

The two events that matter together are a decrypting read and a deletion by the
same principal. Taking the value while it is still readable and then removing the
parameter and its entire version history is a complete collect-and-cover: the data
is exfiltrated and the record of what it was is gone. `sigma_t1485.yml` carries
that as a `temporal_ordered` correlation with a one-hour span, and ships the
decrypting-read base rule locally so the correlation resolves inside its own file.

## Response levers

**Recovery comes from outside AWS or not at all.** `GetParameterHistory` does not
help — the history is deleted with the parameter. The value has to come from the
configuration repository, the system of record for the secret, or a backup. Where
the parameter held a credential, treat recreation and rotation as the same task:
the old value is not merely lost, it is also disclosed if anything read it before
the delete.

**Recreating the name has a wait.** AWS: *"After deleting a parameter, wait for at
least 30 seconds to create a parameter with the same name."* A restore script that
deletes and immediately recreates will fail intermittently, and the failure looks
like a permissions problem.

**Consumers fail later, not now.** An application that has already read the value
keeps working until it restarts or refreshes, so the availability impact surfaces
hours after the deletion, often during the next deploy. Enumerate the consumers
during the incident rather than waiting for them to page.

**Error strings:** `DeleteParameter` — `ParameterNotFound` (**not recorded in
CloudTrail**), `InternalServerError`. `DeleteParameters` — `InternalServerError`
only. Denials are `AccessDenied` (IAM) and `AccessDeniedException`
(service-evaluated); match both and confirm against a real denied event.

**MITRE:** `T1485 — Data Destruction`, which is the source's own mapping and is correct. Verified live 2026-08-30.

**GuardDuty:** no finding type specific to Parameter Store deletion.

**Severity:** the source rule rates this P3. The IR assessment is **High** for a
deletion outside the owning pipeline and **P0** for five or more in five minutes,
because the loss is unrecoverable and the threshold is not a guess — five calls of
the plural API is up to fifty parameters.

## Cross-references

- `../../ssm.discovery.excessive-parameter-creation-detected/` — the write side, and
  the only place a policy-driven expiry is ever visible.
- `../../ssm.credential-access.high-number-of-ssm-parameters-retrieval/` — the read
  side; the decrypting-read base rule here is a local copy of the observable that
  note treats at length.
- `../../ec2.credential-access.imds-credential-theft/` — the instance-profile
  session-name fact (`assumed-role/<Role>/<instance-id>`) applies to every query
  here that keys on `AttributeKey=Username`.

**Files here:**

- `sigma_t1485.yml` — four documents: deletion outside the owning pipeline
  (`high`), an `event_count` correlation at five deletions in five minutes
  (`high`), a `temporal_ordered` read-then-delete correlation (`high`), and the
  decrypting-read base rule it depends on (`low`).
- `kql_t1485.kql` — expands the `names` array so the count is parameters rather
  than calls, reads `deletedParameters` / `invalidParameters` where present, and
  carries the inventory-reconciliation path, the recovery limits and the error set
  inline.

Full response procedure is in `../PLAYBOOK.md`.
