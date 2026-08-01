# Detection Note — T1552.005 (Steal EC2 Instance Credentials via IMDS)

**Signal:** `ssm:SendCommand` dispatching IMDS queries to an instance, followed
by the stolen instance-profile credentials being used from an IP that is not
the instance's.

**The key constraint:** the theft itself happens *on the host* — a curl to
`169.254.169.254` — and never appears in CloudTrail. Detection therefore has
two halves: the dispatch (early, before the credentials are used) and the
off-instance use (late, but definitive).

**Detection layers:**

| Layer | Rule | Timing |
|---|---|---|
| Dispatch by non-automation principal | Sigma Rule A, `medium` | Before theft completes |
| Command body contains an IMDS address | Sigma Rule A2, `high` | Before theft completes |
| Credentials used off-host | `kql_t1552_005.kql` | After exfiltration |
| GuardDuty finding | Sigma Rule B, `critical` | After exfiltration |

**GuardDuty:** `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` —
the definitive signal for this technique, and the one to escalate on.

**Hunting caveat — instance-profile sessions:** CloudTrail
`lookup-events --attribute-key Username` matches the *session name*, which for
an instance profile is the **instance ID**, not the role name. Any query that
filters this role's activity by role name through that attribute returns zero
events. Filter on `sessionContext.sessionIssuer.userName` instead.

**Command-body visibility:** for the standard `AWS-RunShellScript` /
`AWS-RunPowerShellScript` documents the command text is in CloudTrail
`requestParameters`. A custom document using `NoEcho` hides it — source the
body from SSM output logging in that case.

**No error-code variant:** the emulation's SSM/STS calls succeed, so there is
no `errorCode` to key on. Failed IMDS theft against an IMDSv2-hardened host
surfaces as an HTTP 401 in the instance's own logs, not in CloudTrail.

**MITRE note:** the technique name in the manifest is the upstream emulation
label; the canonical T1552.005 name is *Unsecured Credentials: Cloud Instance
Metadata API*, which fits this technique well.

**Files here:**
- `sigma_t1552_005.yml` — three documents (Rule A, Rule A2, GuardDuty Rule B).
  `GetCallerIdentity` and `GetCommandInvocation` are deliberately **not**
  selectors; they are triage context only.
- `kql_t1552_005.kql` — off-instance credential-use correlation. Requires a
  Sentinel watchlist named `InstanceRoleIPs`.

Full response procedure is in `../PLAYBOOK.md`.
