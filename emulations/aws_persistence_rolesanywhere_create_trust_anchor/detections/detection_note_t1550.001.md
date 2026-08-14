# Detection Note: T1550.001 (Create IAM Roles Anywhere Trust Anchor)

**Signal:** `rolesanywhere:CreateTrustAnchor`, a rare API almost never called
outside initial Roles Anywhere setup. A single occurrence justifies triage.

**Why it matters:** a trust anchor registers an **external CA as an AWS
identity source**. The attacker holds a private key, not an AWS credential, so
there is **nothing to rotate**. Key rotation, user deletion and session
revocation all leave it intact.

## It is a chain, not an event

A trust anchor **alone is inert**. Credential vending requires all three:

1. **Trust anchor**, registers the attacker's CA
2. **Profile**, declares which roles may be assumed
3. **A role trusting `rolesanywhere.amazonaws.com`**, the gate

Breaking any link breaks the persistence, and detecting any link catches the
scheme. The original rule covered only the first, and bundled
`DisableTrustAnchor` / `DeleteTrustAnchor`, the teardown, which inverted the
signal, since removing an anchor is remediation.

## Roles Anywhere is regional

A rule or query bound to one region **misses an anchor created anywhere else**.
Deploy across all regions and sweep all regions during hunts (`describe-regions`
loop for anchors and profiles). The IAM role-trust half is global.

## The Sigma trap that silently kills the rule

`UpdateAssumeRolePolicy` carries `policyDocument`. `CreateRole` carries
`assumeRolePolicyDocument`. **No single event has both.**

Sigma ANDs sibling keys in one selection block, so putting both in one block
means **no event ever satisfies it and the rule never fires**, for either
event. They must be OR'd as separate blocks. This is a silent false negative on
a P0 rule; it is the kind of defect that is only found by reading the rule
against real event shapes.

**No decode needed for this one:** the service principal
`rolesanywhere.amazonaws.com` survives URL-encoding as a literal substring, it
is only letters and dots, and nothing percent-encodes.

## Field notes

- **The CA certificate PEM is logged in cleartext** in
  `requestParameters.source.sourceData.x509CertificateData`, it is public
  material, not redacted. Extract and inspect issuer/subject with `openssl`.
- **`CreateSession` has no `requestParameters.subjectName`.** The presenting
  certificate is in `requestParameters.cert`; the certificate CN surfaces as
  **`sourceIdentity`** on the downstream calls made with the vended
  credentials. That is the field to pivot on when tracing what the session did.
- `profileId` is the trailing segment of the profile ARN.
- `get-role` returns the trust policy **decoded**, unlike the CloudTrail event.

**Containment order: disable before delete.** A deleted anchor takes its
evidence with it.

**Prevention:** `aws:SourceArn` binds a role to a *specific* trust anchor, so
the role cannot be assumed via an attacker's newly created one.

**Error strings:** denials surface as `AccessDenied` / `AccessDeniedException`.
Not `Client.`-prefixed like EC2.

**MITRE note:** the manifest maps T1550.001 and tags it *Persistence*, but
T1550.001 is canonically *Application Access Token* with tactics **Defense
Evasion / Lateral Movement**, not Persistence. T1556 or T1098 fit the behaviour
better. Inherited from the upstream catalogue and retained for traceability.

**Severity:** manifest MEDIUM; IR view **High**, credential-free persistence
with nothing to rotate. (The chain caveat applies: an anchor without a profile
and a trusting role is not yet exploitable.)

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1550.001.yml`, three documents: anchor/profile creation (`high`),
  the role-trust gate (`high`, with the OR'd sibling blocks), and
  `CreateSession` vending (`medium`).
- `kql_t1550.001.kql`, whole-chain query over a 30-day window with per-link
  verdicts and the certificate extraction pointer.

Full response procedure is in `../PLAYBOOK.md`.
