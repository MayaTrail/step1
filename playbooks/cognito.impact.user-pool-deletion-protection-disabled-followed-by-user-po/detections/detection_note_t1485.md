# Detection Note — T1485 / T1531 (User Pool Deletion Protection Disabled, Then the Pool Deleted)

**Signal:** the same Cognito user pool having deletion protection deactivated and then being
deleted, within thirty minutes.

**The ordering is mandatory, not incidental, and that is what makes this a high-confidence
sequence rather than a coincidence.** AWS documents it on both `CreateUserPool` and
`UpdateUserPool` in identical words: *"When you try to delete a protected user pool in a
`DeleteUserPool` API request, Amazon Cognito returns an `InvalidParameterException` error. To
delete a protected user pool, send a new `DeleteUserPool` request after you deactivate deletion
protection in an `UpdateUserPool` API request."* And `DeleteUserPool`'s entire request body is
`{"UserPoolId": "..."}` — **there is no force flag and no override**. So on a protected pool the
destruction is necessarily at least two calls, and the disable has no purpose other than to permit
the delete. Most sequence detections are probabilistic; this one is structural.

## What the original rule got right, and the one thing it does not know

The source is a two-stage flow — deletion protection deactivated, then the pool deleted within
thirty minutes, grouped by `requestParameters.userPoolId`. That is a sound design, and it is
reproduced rather than replaced. Grouping by the **pool** rather than the principal is the correct
choice and worth stating, because it is the only grouping that catches a chain split across two
identities: a stolen pipeline credential removes the guardrail and a second principal takes the
destructive action.

What it does not know is that **a configured domain independently blocks deletion**. AWS's own
`DeleteUserPool` example response is:

```json
{"__type": "InvalidParameterException",
 "message": "User pool cannot be deleted. It has a domain configured that should be deleted first."}
```

So against any pool with managed login or a custom domain — which is most user-facing pools — the
real chain is **three** calls: `UpdateUserPool` → `DeleteUserPoolDomain` → `DeleteUserPool`. The
flow still fires, because the intervening call does not break the ordering, but the domain
deletion is an **earlier** warning than either stage the source models, and on its own it is
already an outage: *"After you delete a user pool domain, your managed login pages and
authorization server are no longer available."* A second correlation covers that pair.

The two blocking conditions are also **indistinguishable by error code**. Both return
`InvalidParameterException`, and only the `message` string separates "blocked by deletion
protection" from "blocked by a domain". A rule keyed on the code alone conflates an attacker
meeting a guardrail with an operator meeting a prerequisite; the shipped rule accepts that and
tells the analyst to read the message, and the KQL classifies on it.

## Stage one does far more than remove a guardrail

`UpdateUserPool` is a **full replacement, not a patch**. AWS: *"To avoid setting parameters to
Amazon Cognito defaults, construct this API request to pass the existing configuration of your
user pool, modified to include the changes that you want to make. **Important:** If you don't
provide a value for an attribute, Amazon Cognito sets it to its default value."*

A call carrying only `UserPoolId` and `DeletionProtection: INACTIVE` therefore also resets:

| Reset | Security consequence |
|---|---|
| `MfaConfiguration` | MFA drops to its default state for the whole pool |
| `LambdaConfig` | Every trigger — `PreAuthentication`, `PostAuthentication`, `PreTokenGeneration`, `UserMigration`, the custom SMS/email senders — is unwired, taking any Lambda-based authorization hardening with it |
| `UserPoolAddOns` | This is where **threat protection** lives; an `AUDIT` or `ENFORCED` pool drops to the default |
| `Policies` | Password policy and `SignInPolicy.AllowedFirstAuthFactors` revert to defaults |
| `UserAttributeUpdateSettings` | `AttributesRequireVerificationBeforeUpdate` drops, so email and phone changes stop requiring verification — a documented account-takeover primitive |
| `AccountRecoverySetting` | Reverts to the legacy behaviour where SMS is preferred over email |
| `EmailConfiguration` / `SmsConfiguration` | Verification and MFA message delivery breaks |
| `UserPoolTags` | Tag-based IAM and cost attribution break |
| `UserPoolTier` | AWS documents it as defaulting to `ESSENTIALS`, silently downgrading a `PLUS` pool and its tier-gated features |

**None of that is separately visible in CloudTrail.** A full-replacement write records what was
sent, not what was cleared, so there is no event for "MFA was turned off". Two consequences: the
responder must restore the whole configuration after any `UpdateUserPool`, not just the flag; and
a **tag-based guardrail on user pools is self-defeating**, because the attacker's first call
removes the tag the guardrail reads.

One nuance to keep straight: `UpdateUserPool` carries only the coarse `MfaConfiguration` toggle.
The factor-level settings — `SmsMfaConfiguration`, `SoftwareTokenMfaConfiguration`,
`EmailMfaConfiguration`, `WebAuthnConfiguration` — live in `SetUserPoolMfaConfig`, a separate API
whose reference carries **no** reset-to-default callout. Do not claim full-replacement semantics
for it; AWS does not document them.

## Deletion is recoverable for fourteen days, and this corrects the reflex

This is the single most important operational fact in the technique, and it is the opposite of
what every other destruction playbook in this corpus concludes. `DeleteUserPool`, verbatim:

> *"When you delete a user pool, it's no longer visible or operational in your AWS account. Amazon
> Cognito retains deleted user pools in an inactive state for 14 days, then begins a cleanup
> process that fully removes them from AWS systems. In case of accidental deletion, contact
> Support within 14 days for restoration assistance."*

Read it precisely, because both halves matter:

- **There is a restore path**, and it is the only action that recovers users and their credentials.
  It must be the first step of the response, ahead of any rebuild.
- **It is a support-ticket path**, worded as *"restoration assistance"* rather than a guarantee.
  There is no undelete API, no console recycle bin and no self-service anything. And the pool is
  *"no longer visible or operational"* from the first second, so the outage is real and immediate
  even while the data is retained.

There is **no other recovery**. AWS Backup's supported-resource list contains no Cognito entry, and
that page states *"Support for a feature or service should not be assumed unless explicitly
mentioned."* There is no snapshot, no PITR and no vault for a user pool. The only pre-incident
control that helps is a scheduled `DescribeUserPool` + `DescribeUserPoolClient` snapshot to durable
storage, which AWS itself points at as the way to reconstruct an update request.

## Passwords, precisely

Cognito provides **no export** for password hashes — no `GetUserPassword`, no hash field on any
read API, no export operation. It does support hash **import**: `CreateUserImportJob` accepts
`BCRYPT`, `SCRYPT`, `ARGON2ID` and `PBKDF2_SHA256`, and users imported with hashes land
`CONFIRMED` and can sign in immediately.

State the conclusion carefully or a reader will catch the import capability and discredit the
section: **hashes can be imported from a source system outside Cognito, and can never be extracted
from Cognito.** So in a Cognito-only estate, an IaC rebuild restores the pool's *configuration* and
cannot restore users or credentials. Without hashes, imported users land in `RESET_REQUIRED` and
must reset at first sign-in, and *"the creation date for each user is the time when that user was
imported into the user pool"* — the original account ages are lost, which destroys forensic
timeline data as well as product analytics.

## The identifier surface does not come back

`CreateUserPool` has no parameter for requesting a pool ID; the format is `[\w-]+_[0-9a-zA-Z]+`
and the suffix is service-generated. Whether the same ID could ever be reissued is **not documented
either way** — treat "the ID is gone" as a strong operational assumption rather than a quoted fact.
What *is* documented is what depends on it: an identity pool names a user pool IdP as
`cognito-idp.<region>.amazonaws.com/<user-pool-id>`, and the same ID appears in every OIDC issuer
and JWKS URL and in every shipped client build. A rebuilt pool breaks all of them.

The **domain prefix** is a further unknown. AWS documents the prefix namespace as globally shaped
(`<prefix>.auth.<region>.amazoncognito.com`) and the console requires *"an available domain
prefix"*, but **no AWS statement confirms that a deleted prefix becomes claimable by another
account.** Treat prefix squatting on a recognisable auth domain as an unquantified risk to reclaim
the prefix against, not as a documented fact.

## Field shape — the one unverified thing, and it is load-bearing

AWS publishes **no example CloudTrail event for any `cognito-idp` management operation**. The
`requestParameters` spellings `userPoolId` and `deletionProtection` are the lower-camel forms
consistent with every published `cognito-identity` example (`identityPoolId`,
`allowUnauthenticatedIdentities`) and with the general CloudTrail convention, and they are what the
source rule itself uses — but they are **inferred**. Confirm both in your own trail before
deploying: a group-by on an absent field collapses every pool into one bucket or none, and a value
match on an absent field matches nothing. The KQL coalesces both casings; the Sigma cannot, so map
it to a case-insensitive comparison on any backend that offers one.

Two documented facts do hold: user pool API operations are **management** events, logged by
default, with `eventType: AwsApiCall` (hosted-UI activity is `AwsServiceEvent` under different
names), and private fields are obscured as `HIDDEN_DUE_TO_SECURITY_REASONS`.

## Response levers

**Error strings:** `DeleteUserPool` documents seven operation-specific exceptions: `InternalErrorException`,
`InvalidParameterException`, `NotAuthorizedException`, `OperationNotEnabledException`,
`ResourceNotFoundException`, `TooManyRequestsException`, `UserImportInProgressException`.

`InvalidParameterException` is the guardrail refusal, overloaded across both blocking conditions.
`UserImportInProgressException` is worth knowing for a different reason: a running user-import job
blocks deletion too, which is a third, unintended obstacle an actor may meet.

`UpdateUserPool` documents fourteen, including `ConcurrentModificationException`,
`FeatureUnavailableInTierException`, `TierChangeNotAllowedException`, `UserPoolTaggingException`,
`UserImportInProgressException` and the SMS/email role-policy set. `TierChangeNotAllowedException`
and `FeatureUnavailableInTierException` are the errors a full-replacement call throws when its
silent `UserPoolTier` reset is refused — an accidental tell that the call was not a considered
update.

Denials split. Cognito's service-level authorization failure is `NotAuthorizedException`, and AWS's
own sample CloudWatch Logs Insights query filters CloudTrail on exactly that value for
`cognito-idp`. The Common Error Types list separately carries **`AccessDeniedException`** (HTTP
403). Match both; the bare `AccessDenied` form is not in Cognito's documented list, and no AWS page
confirms which form an IAM-layer denial produces here — verify against a real denied event.

**GuardDuty:** There is **no GuardDuty finding type specific to Cognito user pool deletion.** Identity-side
findings such as `Impact:IAMUser/AnomalousBehavior` may fire on the principal, not on the pool. Do
not build the response on one existing.

**Severity:** **Critical** for the correlation, against the source's **P1**, which is close and defensible. The
gap is not the rating so much as the reasoning behind it: the destruction of an identity provider
is not a resource-availability event, it is the removal of every account's ability to authenticate
anywhere the pool is trusted. The component alerts are rated **P3** by the source and are
separately registered use cases; as base rules here they are `low`, because neither is
self-evidently malicious in isolation and the sequence is the finding.

**MITRE:** Primary **T1485 — Data Destruction** (Impact, TA0040), which is the source's own structured label
and is correct. Secondary **T1531 — Account Access Removal**, also Impact, carried because the
concrete outcome is that every user in the directory loses the ability to sign in — that is
precisely what T1531 describes and it is the half a pure data-destruction reading misses.

Its live replacement is a defensible label for **stage 1 alone** —
deletion protection is a guardrail and turning it off disables a control — and the corpus already
uses T1685 for the standalone deletion-protection use cases in other services. It is not
defensible for this use case as a whole, whose outcome is destruction. The reasoning is recorded
in `../_source/PROVENANCE.md` rather than left as a bare substitution.

**Files here:**

- `sigma_t1485.yml` — six documents: a `temporal_ordered` correlation firing `critical` on
  disable-then-delete within thirty minutes grouped by pool; base rules (`low`) for the
  deletion-protection deactivation, the pool deletion and the domain deletion; a second
  `temporal_ordered` correlation firing `high` on domain-then-pool, which the source flow does not
  model; and a `high` rule for a `DeleteUserPool` refused with `InvalidParameterException`.
- `kql_t1485.kql` — reports the **elapsed seconds** between the disable and the delete, which the
  Sigma correlation cannot, and which separates a scripted destruction from a decommission; flags
  the split-identity chain; keeps refused attempts in their own columns; and computes the
  **14-day AWS Support restore deadline** as a first-class output field.

Full response procedure is in `../PLAYBOOK.md`.
