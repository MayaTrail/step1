# Detection note — ECScape (ECS cross-task credential hijack)

**Techniques:** T1552.007 (Container API), T1552.005 (Cloud Instance Metadata API), T1134 (agent impersonation)

## Why this is hard
The credential delivery itself happens over the ECS **ACS WebSocket** and is **not
recorded in CloudTrail** — the control plane simply streams `IamRoleCredentials`
to what it believes is the agent. So there is no single "creds stolen" event.
Detection relies on the *surrounding* API activity and on cross-task credential
reuse.

## Signals (highest to lowest fidelity)
1. **Cross-task / off-host credential use** — a task role or execution role used
   from a principal, task, or source IP that is not the task it was issued to.
   For task-execution roles this is especially strong: execution-role
   credentials are agent-only and should *never* appear in application API calls.
2. **`ecs:DiscoverPollEndpoint` anomaly** — legitimately called only by the ECS
   agent (instance role) at startup. Alert on unusual **frequency** (a second
   caller/session beyond the agent), or DiscoverPollEndpoint closely followed by
   new outbound TLS to an `ecs-a-*.<region>.amazonaws.com` ACS endpoint from a
   task rather than the agent process.
3. **`ecs:RunTask` of an unexpected task definition** — here, a task whose task
   role is deny-all / newly created, started by an unusual principal.
4. **GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`** —
   fires if the stolen *instance* role credentials are used from off the instance.

## Data sources
- CloudTrail (management events: `DiscoverPollEndpoint`, `RunTask`, and the API
  calls made with the stolen roles).
- VPC Flow Logs / host telemetry for the outbound ACS WebSocket from a task.
- GuardDuty.

## Hardening
- Set the instance IMDS hop limit to 1 and prefer `awsvpc` network mode so tasks
  cannot reach the host IMDS / introspection port.
- Scope task-execution roles tightly (only the secrets each task needs).
- Treat any use of an execution role outside the agent as an incident.
