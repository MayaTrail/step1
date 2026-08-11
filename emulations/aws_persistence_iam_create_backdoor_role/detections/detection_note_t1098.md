# Detection Note: T1098 (Create IAM Backdoor Role with Admin Access)

**Signal:** `iam:CreateRole` with a cross-account trust principal, followed by
`iam:AttachRolePolicy` granting admin.

**This technique is a combination.** It is the external-trust half of
*Backdoor IAM Role Trust Policy* plus the admin half of *Create Admin User*,
applied to a net-new role. Either half alone is suspicious; together they are a
cross-account admin backdoor that survives all credential rotation.

The queries here score both halves per role, because the response differs: an
externally-trusted role with no privileges is a foothold to close, while one
with `AdministratorAccess` is an active emergency.

## The URL-encoding constraint

Same as the sibling technique, and just as silent when ignored.
`assumeRolePolicyDocument` is **URL-encoded** in the event, `"` becomes `%22`,
`*` becomes `%2A`. A substring match on `"AWS":"*"` **never fires**.

Only 12-digit **account IDs** survive encoding verbatim. That is why the Sigma
rule is a known-IOC-account catcher, and why the general external/wildcard case
must decode the document first.

## Parsing shape guards

`Statement` may be an object or an array; `Principal` may be a bare string
(`"*"`), an object, or an object containing an array. Normalise before
inspecting, code assuming one shape crashes or silently skips on the others.

## Nested response path

`CreateRole` nests the created role: `responseElements.role.roleName`. The flat
path returns `null`.

## Coverage beyond CloudTrail

**IAM Access Analyzer** evaluates **existing** roles, not just new changes, it
finds backdoors planted before logging was in place, which the event-driven
rules structurally cannot. Use `accessanalyzer list-findings-v2` for the sweep.

**Was it used?** The cross-account `AssumeRole` rule confirms exploitation: in
this account, an external assumption records the caller's account id in
`userIdentity.accountId` while the role is local.

**Containment caution:** if the caller was **root** or a **federated identity**,
the standard "disable the access key" containment step does not apply, there
is no access key. Revoke sessions and address the trust relationship instead.

**A note on the guardrail SCP:** the one in the playbook *adapts* rather than
mirrors the reference pattern, it adds a break-glass carve-out, where the
reference version is unconditional. Deploy the carve-out deliberately or not at
all; a half-applied version is worse than either.

**Error strings:** IAM denials surface as `AccessDenied` /
`AccessDeniedException`; a bad trust document as `MalformedPolicyDocument`.
Not `Client.`-prefixed like EC2.

**MITRE:** T1098 (*Account Manipulation*) is defensible; T1136.003 (*Create
Account: Cloud Account*) is arguably as good a fit given the role is net-new.

**Severity:** manifest MEDIUM; IR view **High**, cross-account admin
persistence surviving credential rotation.

**GuardDuty:** no finding type specific to this technique.

## Tuning the allowlist

The rule ships `:role/REPLACE-ME-*` placeholders, not defaults. They match
nothing, so an unedited rule has no exclusions at all and alerts on the routine
activity it is supposed to ignore.

Derive the real list from your own trail. The principals that show up
repeatedly, across weeks rather than once, are your automation:

```bash
# GNU date first, BSD/macOS date second. The two take different flags.
START=$(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-90d +%Y-%m-%dT%H:%M:%SZ)

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AttachRolePolicy \
  --start-time "$START" \
  --output json | \
  jq -r '.Events[].CloudTrailEvent | fromjson | .userIdentity.arn' | \
  sort | uniq -c | sort -rn
```

Keep the recurring service and pipeline roles. Leave out anything human unless
it is a documented break-glass path, since a human name on the allowlist is a
standing hole in the rule.

Re-check the list when provisioning changes. A retired pipeline role left in
place is dead weight; a new one missing from it produces the false-positive
wave that gets a rule muted.

## Why the Sigma and the KQL disagree

The Sigma rule filters by caller identity, using the allowlist above. The KQL
does not filter by identity at all. It keys on what the role receives, an
external-account trust or an admin-equivalent policy, rather than who created
it.

That is deliberate, not an oversight. The KQL needs no knowledge of your role
names, so it is useful on the first day in an account nobody has profiled yet.
The cost is that a backdoor role trusting a principal inside your own
organization is not flagged.

Deploy either, or both. Do not expect them to fire on the same set of events,
and do not treat a disagreement between them as a bug.

**Files here:**
- `sigma_t1098.yml`, five documents: the known-bad-account IOC catcher
  (`critical`), admin attach (`critical`), the `temporal_ordered` sequence
  (`critical`), the `CreateRole` base rule (`low`), and cross-account
  `AssumeRole` usage (`high`). Replace the placeholder account IDs.
- `kql_t1098.kql`, decodes the trust policy and scores both halves per role.

Full response procedure is in `../PLAYBOOK.md`.
