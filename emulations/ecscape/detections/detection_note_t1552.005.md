# Detection note — ECScape, IMDS instance-credential theft (T1552.005)

**Technique:** T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
**Role in ECScape:** step 1 of the chain. Before it can impersonate the ECS agent,
the attacker container reads the **EC2 instance role** from IMDS
(`http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`). Host
network mode + a hop limit > 1 make IMDS reachable from inside the task.

## Why CloudTrail cannot see the theft
The IMDS read is a link-local HTTP GET on the instance. It produces **no AWS API
call and no CloudTrail event.** There is nothing to alert on at the moment of
theft. Detection is therefore indirect:

1. **GuardDuty `InstanceCredentialExfiltration`** — the definitive signal, and the
   only one that fires on the theft itself, *but only if the stolen instance
   credentials are used from a source AWS does not expect* (another account, or
   off the instance). In a pure ECScape run the instance creds are used **on the
   instance** (to call `ecs:DiscoverPollEndpoint` and open the ACS WebSocket), so
   GuardDuty may stay silent — do not rely on it alone here.
2. **Instance-role credentials doing agent-only work from a task context** — the
   instance role calling `ecs:DiscoverPollEndpoint` a second time (the agent does
   it once at boot) is the on-instance tell. That correlation lives in the
   T1552.007 rules; this note exists because the *credential source* is IMDS.
3. **Off-host use** of the instance role (any `sourceIPAddress` that is not the
   instance's private IP / NAT) — see `kql_t1552.005.kql`.

## The real fix is network isolation, not IMDSv2 alone
Enforcing IMDSv2 (`HttpTokens: required`) does **not** stop ECScape — the payload
handles IMDSv2 tokens. What stops it is denying the container a path to IMDS:
- **`awsvpc` network mode** (each task gets its own ENI; the task cannot reach the
  host's IMDS or the `:51678` introspection port), or **Fargate** (immune), and
- **`HttpPutResponseHopLimit: 1`** on the instance, so a containerised process one
  hop away from the host cannot reach 169.254.169.254.

## Data sources
- GuardDuty (`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.*`).
- CloudTrail (instance-role session activity, for off-host correlation).
- VPC Flow Logs (task egress to the ACS endpoint).
