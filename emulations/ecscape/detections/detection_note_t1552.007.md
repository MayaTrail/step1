# Detection note — ECScape, ECS agent impersonation (T1552.007)

**Technique:** T1552.007 — Unsecured Credentials: Container API
**Role in ECScape:** the core. Using the instance role stolen in step 1
([T1552.005](detection_note_t1552.005.md)), the attacker container reads the ECS
**agent introspection API** (`http://<host>:51678/v1/metadata`) for the
container-instance identity, calls `ecs:DiscoverPollEndpoint`, then opens a
SigV4-signed **ACS WebSocket** (`wss://ecs-a-*.<region>.amazonaws.com/ws?...&sendCredentials=true`).
AWS accepts it as the agent and streams the role + execution-role credentials of
**every task on the host**.

## Why this is hard
The credential delivery happens over the ACS WebSocket and is **not recorded in
CloudTrail** — the control plane simply streams `IamRoleCredentials` to what it
believes is the agent. There is no single "creds stolen" event. Detection relies
on the *surrounding* API activity and on misuse of the harvested roles.

## Signals (highest to lowest fidelity)
1. **Execution-role credentials used outside agent bootstrap** — a task-execution
   role is agent-only; ECS uses it at task start (ECR pull, log streams, secret
   resolution) and never exposes it to app code. Any other use = the credentials
   left the agent. Highest-fidelity single signal (`sigma_t1552.007.yml` rule 3).
2. **Cross-task / off-host role use** — a task role appearing from a source IP or
   task other than the one it was issued to (`kql_t1552.007.kql`).
3. **`ecs:DiscoverPollEndpoint` rate anomaly** — the agent calls it once per
   instance boot; a second/repeated call from the same principal is the tell
   (`sigma_t1552.007.yml` rules 1–2). Pair with new outbound TLS to an
   `ecs-a-*.<region>.amazonaws.com` ACS endpoint from a task rather than the agent.
4. **`ecs:RunTask` of an unexpected task** — the operator launching the deny-all
   attacker task, from a non-deployment principal (`sigma_t1552.007.yml` rule 4).

## Data sources
- CloudTrail (`DiscoverPollEndpoint`, `RunTask`, and the API calls the stolen roles make).
- VPC Flow Logs / host telemetry for the outbound ACS WebSocket from a task.
- GuardDuty (backstop, see [T1552.005](detection_note_t1552.005.md)).

## Hardening
- Use **`awsvpc` network mode** (per-task ENI) or **Fargate** so a task cannot
  reach the host IMDS / `:51678` introspection port; set IMDS
  `HttpPutResponseHopLimit: 1`.
- Scope task-execution roles tightly (only the secrets each task needs) and treat
  any use of an execution role outside the agent as an incident.
- Avoid co-locating high-privilege tasks with untrusted ones on a shared EC2 host.
