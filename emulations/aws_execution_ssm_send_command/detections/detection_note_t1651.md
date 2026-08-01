# Detection Note — T1651 (Execute Commands on EC2 Instances via SSM)

**Signal:** `ssm:SendCommand` dispatching `AWS-RunShellScript` /
`AWS-RunPowerShellScript` from a non-automation principal — especially across
several instances at once.

**Three discriminators, in order of usefulness:**

1. **Document** — the shell documents are the arbitrary-code ones. Everything
   else in the SSM document catalogue is far narrower.
2. **Principal** — patch automation runs this constantly and legitimately. The
   allowlist is what makes the rule deployable.
3. **Fan-out** — one instance is administration; several at once is fleet-wide
   execution.

The original rule had none of these: it matched three SSM event names with a
bare `condition: selection`, the same broken pattern shipped with the SSM
credential-theft and recon techniques.

**Targeting has two shapes.** `requestParameters.instanceIds` is an explicit
list — count it. `requestParameters.targets` is a **tag-based selector**, which
can be fleet-wide regardless of how many explicit instances are named. Its mere
presence should be treated as fan-out; a rule that only counts `instanceIds`
misses the broadest case entirely.

**Command bodies are unreliable in CloudTrail.** SSM often omits
`requestParameters.parameters.commands`, and a custom document using `NoEcho`
hides it deliberately. A rule keyed on that field silently matches nothing
wherever it is absent — so treat content matching as a *bonus* layer, never the
primary detection. Where SSM output logging to S3/CloudWatch is enabled, run
content matching against the logged command text instead; that source is
reliable.

**The pivot from an alert to what actually ran** is the `commandId` in
`responseElements.command.commandId` — feed it to `ssm list-command-invocations
--details` or the output logs.

**Fan-out threshold:** the rules use `>= 3`, which fires on the three-instance
emulation. Tune it to your real maintenance-window batch sizes — this is the
one number most likely to need local adjustment.

**Error strings:** SSM denials surface as `AccessDeniedException`; an
unreachable or unmanaged target as `InvalidInstanceId`. These are SSM service
errors and are **not** `Client.`-prefixed like EC2 errors.

**Hunting caveat — instance-profile sessions:** CloudTrail
`lookup-events --attribute-key Username` matches the *session name*, which for
an instance profile is the **instance ID**, not the role name. Filter on
`sessionContext.sessionIssuer.userName` instead.

**MITRE note:** T1651 (*Cloud Administration Command*) is the correct mapping
here — no caveat needed, unlike most of this set.

**Severity:** manifest MEDIUM; IR view **High** — arbitrary command execution
across managed instances.

**GuardDuty:** no finding type specific to this technique.

**Files here:**
- `sigma_t1651.yml` — three documents: the document+principal rule (`high`),
  best-effort command-body content matching (`high`), and the demoted
  enumeration/result-retrieval context rule (`low`).
- `kql_t1651.kql` — adds the fan-out logic covering both explicit-instance and
  tag-based targeting.

Full response procedure is in `../PLAYBOOK.md`.
