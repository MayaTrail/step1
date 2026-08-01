# Detection Note — T1098 (Backdoor IAM Role Trust Policy)

**Signal:** `iam:UpdateAssumeRolePolicy` (or `CreateRole`) adding an external
account or a wildcard principal to a role's trust policy.

**Why this is serious:** the backdoor lives in the **role's trust policy**, not
in any credential. Rotating keys, deleting users and revoking sessions do not
touch it. It survives the entire standard credential-rotation response and
grants the attacker a way back in afterwards.

## The URL-encoding constraint

This is the single most important implementation detail, and it silently breaks
rules that ignore it.

`policyDocument` is **URL-encoded** in the CloudTrail event. Percent-encoding
escapes the structural characters:

| Character | Encoded |
|---|---|
| `"` | `%22` |
| `*` | `%2A` |
| `:` | `%3A` |

So a substring pattern like `'"AWS":"*"'` **never matches the raw event**. A
Sigma rule written that way detects nothing at all, silently.

What survives encoding verbatim: **12-digit account IDs** — plain digits are
not escaped. That is the whole reason the Sigma rule here is scoped to
*known-bad account IDs* and nothing more.

The general case — *any* account outside the org, or a wildcard — **requires
decoding** the document. That is the KQL path, and it is the standing
detection. The Sigma rule is an IOC catcher only.

## Two different request keys

`UpdateAssumeRolePolicy` stores the trust policy in
`requestParameters.policyDocument`. `CreateRole` stores it in
`requestParameters.assumeRolePolicyDocument`. **No single event has both.**

They must be OR'd as sibling blocks. ANDing them inside one selection — which
Sigma does implicitly for sibling keys — means the rule never fires for either
event. This is an easy and completely silent failure.

**Include `CreateRole`.** An attacker can create a *new* role trusting
themselves, evading any Update-only rule.

## Parsing caution

`Statement` may be a single **object** or an **array**, and `Principal` may be
a bare string (`"*"`), an object, or an object containing an array. Any jq or
KQL that assumes one shape crashes or silently skips on the others. Normalise
before inspecting.

## Coverage beyond CloudTrail

**IAM Access Analyzer** is the purpose-built detector for exactly this
condition, and it has an advantage the event-driven rules do not: it evaluates
**existing** roles, not only new changes. A backdoor planted before logging was
in place is invisible to CloudTrail rules and visible to Access Analyzer.

**Was it used?** The `AssumeRole` rule detects exploitation. In the role
owner's account, a cross-account assumption records the external caller's
account in `userIdentity.accountId` while the role belongs to yours.

**Error strings:** IAM denials surface as `AccessDenied` (IAM-policy denial) or
`AccessDeniedException`; a bad policy as `MalformedPolicyDocument`. Not
`Client.`-prefixed like EC2.

**MITRE:** T1098 (*Account Manipulation*) is correct — no caveat.

**Severity:** manifest MEDIUM; IR view **High** — durable cross-account
persistence that survives credential rotation.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1098.yml` — two documents: the known-bad-account IOC catcher
  (`critical`) and cross-account `AssumeRole` usage (`high`). Replace the
  placeholder account IDs before deploying.
- `kql_t1098.kql` — the authoritative decode-and-compare detection covering
  wildcards and arbitrary external accounts.

Full response procedure is in `../PLAYBOOK.md`.
