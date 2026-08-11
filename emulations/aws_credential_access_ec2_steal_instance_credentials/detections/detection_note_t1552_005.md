# Detection Note: T1552.005 (Steal EC2 Instance Credentials via IMDS)

**Signal:** `ssm:SendCommand` dispatching IMDS queries to an instance, followed
by the stolen instance-profile credentials being used from an IP that is not
the instance's.

**The key constraint:** the theft itself happens *on the host*, a curl to
`169.254.169.254`, and never appears in CloudTrail. Detection therefore has
two halves: the dispatch (early, before the credentials are used) and the
off-instance use (late, but definitive).

**Detection layers:**

| Layer | Rule | Timing |
|---|---|---|
| Dispatch by non-automation principal | Sigma Rule A, `medium` | Before theft completes |
| Command body contains an IMDS address | Sigma Rule A2, `high` | Before theft completes |
| Credentials used off-host | `kql_t1552_005.kql` | After exfiltration |
| GuardDuty finding | Sigma Rule B, `critical` | After exfiltration |

**GuardDuty:** `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`,
the definitive signal for this technique, and the one to escalate on.

**Hunting caveat, instance-profile sessions:** CloudTrail
`lookup-events --attribute-key Username` matches the *session name*, which for
an instance profile is the **instance ID**, not the role name. Any query that
filters this role's activity by role name through that attribute returns zero
events. Filter on `sessionContext.sessionIssuer.userName` instead.

**Command-body visibility:** for the standard `AWS-RunShellScript` /
`AWS-RunPowerShellScript` documents the command text is in CloudTrail
`requestParameters`. A custom document using `NoEcho` hides it, source the
body from SSM output logging in that case.

**No error-code variant:** the emulation's SSM/STS calls succeed, so there is
no `errorCode` to key on. Failed IMDS theft against an IMDSv2-hardened host
surfaces as an HTTP 401 in the instance's own logs, not in CloudTrail.

**MITRE note:** the technique name in the manifest is the upstream emulation
label; the canonical T1552.005 name is *Unsecured Credentials: Cloud Instance
Metadata API*, which fits this technique well.

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
  --lookup-attributes AttributeKey=EventName,AttributeValue=SendCommand \
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
does not filter by identity at all. It keys on where the credential is used
from, comparing each call's source IP against an `InstanceRoleIPs` watchlist
holding the addresses that belong to each role.

That is deliberate, not an oversight. The KQL needs no knowledge of your role
names, so it is useful on the first day in an account nobody has profiled yet.
The cost is that you have to populate and maintain that watchlist.

Deploy either, or both. Do not expect them to fire on the same set of events,
and do not treat a disagreement between them as a bug.

**Files here:**
- `sigma_t1552_005.yml`, three documents (Rule A, Rule A2, GuardDuty Rule B).
  `GetCallerIdentity` and `GetCommandInvocation` are deliberately **not**
  selectors; they are triage context only.
- `kql_t1552_005.kql`, off-instance credential-use correlation. Requires a
  Sentinel watchlist named `InstanceRoleIPs`.

Full response procedure is in `../PLAYBOOK.md`.
