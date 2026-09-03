# Detection Note — T1485 / T1531 (Identity Pool Deletion)

**Signal:** `DeleteIdentityPool` succeeding for a principal that does not own identity-pool
lifecycle.

**This is the destruction with no way back, and its user-pool neighbour is not.** AWS on identity
pools: *"You can't undo identity pool deletion. After you delete an identity pool, all apps and
users that depend on it stop working"*, and the console warning is *"you will permanently delete
your identity pool and all the user data it contains."* There is no retention window, no recycle
bin, no undelete API and no Support restore path. Compare
`../../cognito.impact.user-pool-deletion-protection-disabled-followed-by-user-po/`, where AWS
*"retains deleted user pools in an inactive state for 14 days"* and offers restoration assistance:
**do not carry that reflex across.** Opening a Support case here recovers nothing, and the minutes
spent doing it are minutes not spent on the orphaned roles.

There is no deletion-protection flag either. Identity pools have no such concept, so there is no
preceding disable to correlate on and the whole sequence thesis of the user-pool playbook is
inapplicable. The only preventative control is an SCP on the action itself.

## What the original rule got wrong

It matches `DeleteIdentityPool` with a success filter and nothing else, and groups by
`userIdentity.arn`.

| Defect | Consequence |
|---|---|
| The pool is never surfaced, though `requestParameters.identityPoolId` carries it | The alert says a pool is gone and cannot say which one. Every downstream step — which clients break, which roles are orphaned, what the pool was configured to hand out — needs that ID, and the responder has to go and find it |
| No principal check | Fires on every ephemeral test-stack teardown and every Terraform destroy. In an account where identity-pool lifecycle belongs to a pipeline, the caller is the entire signal and it is used only as a grouping key |
| No volume logic | Three pools destroyed in ten minutes and one destroyed in ten minutes are the same alert, though only one of them is a machine-speed run |
| Denials are excluded by the success filter and are not captured anywhere | A principal walking the account's identity pools to find one it can destroy produces the same volume as a real destruction and is invisible |
| P3 priority | A permanent, unrecoverable destruction of a federation resource is triaged alongside configuration noise |

## The part of the blast radius that outlives the incident

**The IAM roles are not deleted with the pool.** They remain, with their attached and inline
policies intact and their trust policies pointing at an `aud` that no longer exists. Most of the
time that is untidy rather than dangerous. Two shapes are dangerous, and **neither is visible in
any Cognito event**:

1. **A role whose trust policy carries no `cognito-identity.amazonaws.com:aud` condition.** AWS:
   *"AWS STS permits web identities to assume roles that are not secured with conditions, but those
   roles can't be modified without introducing those conditions."* An unpinned role is assumable
   through **any** identity pool — including one an attacker creates in their own account. IAM
   enforces the condition on new trust policies, so this only exists on roles predating that
   enforcement; the deletion is exactly the moment somebody looks at them.
2. **A role with no `ForAnyValue:StringLike` condition on `cognito-identity.amazonaws.com:amr`.**
   AWS documents `amr` as the field Cognito sets to `authenticated` or `unauthenticated`, and it is
   what keeps a guest token from satisfying the authenticated role's trust. Without it the
   distinction does not exist.

The documented trust-policy shape to compare against is:

```json
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
 "Principal":{"Federated":"cognito-identity.amazonaws.com"},
 "Action":"sts:AssumeRoleWithWebIdentity",
 "Condition":{"StringEquals":{"cognito-identity.amazonaws.com:aud":"us-east-1:12345678-corner-cafe-123456790ab"},
              "ForAnyValue:StringLike":{"cognito-identity.amazonaws.com:amr":"unauthenticated"}}}]}
```

`../PLAYBOOK.md`'s Query 2 sweeps IAM for both shapes. It is the one investigation step that
matters more after the deletion than before it.

## The magnitude of the loss cannot be measured after the fact

There is no `AWS/Cognito` metric for identity pools, and AWS states plainly that **"no log export
capabilities exist for identity pools."** `GetId`, `GetCredentialsForIdentity`, `GetOpenIdToken`,
`GetOpenIdTokenForDeveloperIdentity` and `UnlinkIdentity` are CloudTrail **data events** — off by
default, billable, and requiring an advanced event selector on
`resources.type = AWS::Cognito::IdentityPool`. Without one there is no record that the pool was
ever used, by whom, or how often, and after the deletion none can be created. **Absence of those
events is not evidence of non-use**, and it must not be written into the incident record as zero.

The `DeveloperProviderName` and every `LookupDeveloperIdentity` mapping between backend user IDs
and Cognito identity IDs go with the pool. That name was already immutable in life — AWS: *"Once
you have set a developer provider name, you cannot change it"* — so it cannot be recreated on a new
pool without also recreating the linkage table from your own systems.

## The pool ID does not come back

`CreateIdentityPool` has **no `IdentityPoolId` request parameter**; the ID is service-generated in
the `REGION:GUID` form (pattern `[\w-]+:[0-9a-f-]+`) and returned only in the response. AWS never
states that an ID cannot be reissued, so treat "the ID is gone" as a strong operational assumption
rather than a quoted fact — what is certain is that there is no mechanism to ask for one. The
consequence is concrete: the pool ID is not confidential and is routinely hard-coded into mobile
binaries and JavaScript bundles, so a rebuild requires a client re-release, not a config push.

## Field shape — verified for this service

Unlike `cognito-idp`, AWS publishes a real CloudTrail example for `CreateIdentityPool`, and it
settles the casing:

```json
"eventSource": "cognito-identity.amazonaws.com", "eventName": "CreateIdentityPool",
"requestParameters": {"identityPoolName": "TestPool", "allowUnauthenticatedIdentities": true,
                      "supportedLoginProviders": {"graph.facebook.com": "000000000000000"}},
"responseElements": {"identityPoolId": "us-east-1:1cf667a2-49a6-454b-9e45-23199EXAMPLE", ...}
```

Lower-camel, on both sides. There is no published example for `DeleteIdentityPool` specifically, so
`requestParameters.identityPoolId` is inferred from the family convention — a far stronger
inference than anything available on the user-pool side, but still an inference.

`UpdateIdentityPool` and `SetIdentityPoolRoles` are both **full-replacement writes**.
`UpdateIdentityPool` requires `IdentityPoolId`, `IdentityPoolName` **and**
`AllowUnauthenticatedIdentities`, and carries AWS's *"If you don't provide a value for a parameter,
Amazon Cognito sets it to its default value"* callout. `SetIdentityPoolRoles` requires its whole
`Roles` map, capped at two entries, so a call sending only `authenticated` removes the
`unauthenticated` mapping. Treat either event as a whole-configuration change, never a field edit.

## Response levers

**Error strings:** `DeleteIdentityPool` documents five operation-specific exceptions: `InternalErrorException` (500),
`InvalidParameterException` (400), `NotAuthorizedException` (400), `ResourceNotFoundException`
(400), `TooManyRequestsException` (400).

The one worth writing down is that **an authorization failure is `NotAuthorizedException` at HTTP
400, not a 403** — a rule keyed on the status code misses it. Match the exception name, and match
`AccessDeniedException` alongside it for the IAM-layer form. `ResourceNotFoundException` is the
expected response to any read of a pool that has already been deleted; in a recovery check that is
a specific, meaningful state and must never reach the same branch as a clean result.

The neighbouring APIs add `ConcurrentModificationException` (`UpdateIdentityPool`,
`SetIdentityPoolRoles`), `LimitExceededException` (`CreateIdentityPool`, `UpdateIdentityPool`) and
`ResourceConflictException` (`CreateIdentityPool`, `UpdateIdentityPool`, `SetIdentityPoolRoles`).

**GuardDuty:** There is **no GuardDuty finding type specific to Cognito identity pool deletion.** Identity-side
findings such as `Impact:IAMUser/AnomalousBehavior` may fire on the principal, not on the pool. Do
not build the response on one existing.

**Severity:** **High**, against the source's **P3**. Irreversibility does not scale with count: one identity pool
destroyed is already unrecoverable, and the difference between one and five is the size of the
work-list. The volume correlation is `critical` because three in ten minutes is machine speed
against a resource with no recovery path, and the reconfigure-then-destroy correlation is `high`
because CloudTrail cannot distinguish evidence destruction from a remediation.

**MITRE:** Primary **T1485 — Data Destruction** (Impact, TA0040), which is the source's own structured label
and is correct. Secondary **T1531 — Account Access Removal**, also Impact, carried because the
concrete outcome is that every federated identity loses its route to AWS credentials — that is what
T1531 describes, and a pure data-destruction reading misses it.

No substitution was needed; the source's label is live and accurate as far as it goes.

**Files here:**

- `sigma_t1485.yml` — five documents: the non-pipeline deletion (`high`); a configuration-write
  base rule (`low`) covering `CreateIdentityPool`, `UpdateIdentityPool` and `SetIdentityPoolRoles`;
  a `temporal_ordered` correlation firing `high` on reconfigure-then-destroy within twenty-four
  hours grouped by pool; an `event_count` correlation firing `critical` at three deletions in ten
  minutes by one principal; and a `medium` rule for refused deletions, which the source's success
  filter discards.
- `kql_t1485.kql` — names the pool, which the source rule does not, and joins each deletion back to
  the pool's own configuration history so the guest-access flag and the role ARNs survive the
  resource that carried them.

Full response procedure is in `../PLAYBOOK.md`. The sibling
`../../cognito.persistence.identity-pool-configured-to-allow-unauthenticated-access/` covers the
same resource in the opposite direction — a pool made more reachable and left live — and its
detection note carries the unauthenticated-role blast-radius analysis in full.

Full response procedure is in `../PLAYBOOK.md`.
