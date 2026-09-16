# Provenance

| Field | Value |
|-------|-------|
| Source type | Internal alert-definition set, not a public rule corpus |
| Dialect | Lucene query strings with per-alert priority, group-by keys and MITRE labels |
| Scope captured | One alert |
| Retrieved | 2026-08-29 |
| Copy retained | `original_rules.yml` — **de-identified extract**, not verbatim |

## Alerts captured

| Alert | Priority | Type | Threshold | Group-by | Source MITRE label |
|-------|----------|------|-----------|----------|--------------------|
| Identity Pool Configured to Allow Unauthenticated Access | P2 | per-event (threshold 0 in 10m) | — | `userIdentity.arn` | T1098/TA0003 |

## Tier decision — **promoted to Tier 1**, on three of the five tests

The register proposed Tier 1 for this row and the proposal is confirmed on the merits.
`07-TIERS.md` requires that the applicable tests be named, so:

**Test 1 — account takeover is reachable in one further hop.** It is reachable in **zero** hops.
`AllowUnauthenticatedIdentities: true` plus an attached unauthenticated role means any caller who
knows the pool ID calls `GetId` and then `GetCredentialsForIdentity` and receives a real `ASIA…`
access key, secret and session token. AWS states both preconditions without hedging: *"Anyone who
knows your identity pool ID can request unauthenticated credentials. Your identity pool ID isn't
confidential information"*, and *"Activate guest access only when you are confident that you would
grant the permissions in your IAM role to anyone on the internet."* Both APIs carry *"This is a
public API. You do not need any credentials to call this API."* There is no credential to steal and
no privilege to escalate — the configuration *is* the account access.

**Test 3 — the blast radius is not in the event, and getting it after containment is impossible.**
`SetIdentityPoolRoles` records role ARNs and nothing else: its `Roles` map is documented as a
*"String to string map"* with value length 20–2048, which is an ARN and not a policy document, and
**no** identity-pool API — `CreateIdentityPool`, `UpdateIdentityPool`, `DescribeIdentityPool`,
`SetIdentityPoolRoles`, `GetIdentityPoolRoles` — returns a policy document at all. The responder
must go to IAM for it. And because `SetIdentityPoolRoles` is a **full-replacement** write, the
containment step that clears the `unauthenticated` mapping erases the only pointer from the pool to
the role, so the capture has to happen first. That is the test almost verbatim.

**Test 5 — a structural blind spot worth a page of honesty.** Credential issuance is invisible by
default. AWS logs `GetId`, `GetCredentialsForIdentity`, `GetOpenIdToken`,
`GetOpenIdTokenForDeveloperIdentity` and `UnlinkIdentity` as **data events**, which *"CloudTrail
doesn't log by default"* and which need an advanced event selector on
`resources.type = AWS::Cognito::IdentityPool`. And in the default **enhanced** flow Cognito calls
`AssumeRoleWithWebIdentity` on your behalf, so no STS event is attributable to your caller either.
In a default-configured account, exploitation of this misconfiguration leaves **no CloudTrail
record at all** — while the *less* secure basic flow, where the client makes its own STS call, is
fully visible in a default trail. That inversion needed writing down properly.

**Test 2 also applies** and is reflected in §3's step ordering: the `aws:TokenIssueTime` revocation
is ineffective unless the issuance cut lands first, because a credential re-fetched afterwards
carries a newer issue time (E4).

Tests 4 (evidence destroyed by the remediation) is a partial match — the containment write erases
the pool→role pointer — and is handled by capturing first rather than by claiming the test.

## Merge assessment — **no merge**

One source rule, one use case, one playbook. Both of `07-TIERS.md`'s tests were applied against
every neighbouring Cognito rule and none passes.

| Considered | Verdict |
|------------|---------|
| `../../cognito.impact.identity-pool-deletion-detected/` | **Separate, and the opposite direction.** Same resource and the same API family, but that use case is about a pool that no longer exists and this one is about a pool that is live and abusable. Different observable (`DeleteIdentityPool` versus a flag value on `Create`/`Update` plus `SetIdentityPoolRoles`), opposite response — that one rebuilds a destroyed resource, this one revokes and re-scopes a live role — and no shared containment step. They are cross-referenced in both directions because a deletion following a guest-access change is anti-forensic cleanup rather than destruction |
| the identity-provider use case (not in this set) | **Separate.** Adding or modifying an IdP changes who can become an *authenticated* identity; this changes whether anyone need authenticate at all. Different observable, different blast radius, and the response to a rogue IdP is to remove the provider rather than to revoke a role |
| the auth Lambda-trigger use case (not in this set) | **Separate.** A different service surface entirely (`cognito-idp.amazonaws.com`), and a trigger runs *during* authentication rather than replacing the need for it |

Test 1 (same observable, same response, differing only in threshold or priority) fails on the
observable for every candidate: no other rule in the set fires on
`allowUnauthenticatedIdentities`. Test 2 does not apply — this is not a flow rule and no
correlation composes it.

## What the source rule gets right, and the one thing it stops short of

Recorded here because the extract is what the `Detection Rule Quality Notes` table is auditable
against, and because credit and criticism both have to be checkable.

**Right:** the field spelling. AWS publishes a real `CreateIdentityPool` CloudTrail event, and it
confirms `requestParameters.allowUnauthenticatedIdentities` in lower camel with an unquoted boolean
— a quoted `'true'` would match nothing on a JSON-typed backend. The rule also covers both `Create`
and `Update` and carries a success filter.

**Short:** it watches only the flag. `CreateIdentityPool` has **no `Roles` parameter at all**;
roles are attached by a separate `SetIdentityPoolRoles` call, and until one lands a guest request
fails with `InvalidIdentityPoolConfigurationException`. So the rule alerts on the announcement and
is silent on the weaponisation — and the single most dangerous change in the technique, attaching
an unauthenticated role to a pool that was *already* guest-enabled, produces no event it matches.
The shipped detection adds that rule and an unordered `temporal` correlation over both.

## Threshold, as inherited

The alert is `logs_threshold` with a threshold of `0.0` over a 10-minute window — the source
format's way of expressing a per-event rule, not a volume condition. The extract records the `0.0`
verbatim rather than normalising it, because a reader auditing the claim that this rule has no
volume logic needs to see the number the source carried. The shipped rules are likewise per-event,
with the only correlation being the unordered pairing of the two configuration halves.

## Attribution and de-identification

**No source, vendor, product, repository or package is named in any file in this project —
including this one.**

`original_rules.yml` departs from the kit's "save the source rule verbatim" instruction (workflow
step 0) deliberately, for the reason given in the authoring brief: the originals are packaged in a
proprietary format whose scaffolding — payload field lists, entity labels, product-specific field
prefixes, internal enums and packaging metadata — identifies the source on sight while bearing on
nothing about whether the rules are correct. What is retained is the complete detection logic:
name, priority, type, MITRE label, the query verbatim, threshold, window and group-by.

No MITRE substitution was needed: the source's structured label is `T1098/TA0003`, and T1098 is
live and is the correct primary. `../PLAYBOOK.md` §6 adds the second mapping and records why
T1098.001 and T1098.003 were considered and rejected; that reasoning is there, not here.

The shipped `references:` blocks in `../detections/` cite public MITRE and AWS documentation only —
a deployed rule travels outside the organisation that wrote it, and an internal path is not
resolvable to whoever receives it.

**Tier:** 1, on criterion 1 of `07-TIERS.md` — *account takeover is reachable in one further hop*.
