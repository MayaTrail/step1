# IR Playbook: Member Account Tries to Leave Its AWS Organization — `organizations:LeaveOrganization`

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Defense impairment (an attempt to take a member account out from under the organization's SCPs, organization trail and delegated security services) |
| Threat Actor | N/A — single technique, not actor-attributed (Stratus Red Team `aws.defense-evasion.organizations-leave`) |
| Platform | aws |
| Severity | High for a refused attempt — the control held, but the principal is hostile and is probing the organization's boundary. Critical if the call succeeded: every organization-level control over that account is gone at once |
| MITRE Tactics | Defense Impairment |
| MITRE Techniques | T1666 |
| Services in Scope | Organizations, IAM, STS, CloudTrail (organization trail and member trails), GuardDuty, Security Hub, AWS Config (delegated administration) |

**What the technique does:** a principal in a member account calls
`organizations:LeaveOrganization`. If it succeeds, the account becomes standalone: the
organization's SCPs no longer apply to it, the organization trail stops recording it, and
delegated GuardDuty, Security Hub and Config aggregation lose it. Every guardrail the security team
built at the organization level stops at the account boundary. The call takes no parameters; it
only works from inside the member account and only if nothing denies it.

**How this emulation runs it — and why it can never succeed.** The connected role assumes
`stratus-red-team-org-leave-attacker-role` (session `atomic-t1666-org-leave`). That role's inline
policy **allows** `organizations:DescribeOrganization` and carries an **explicit Deny** on
`organizations:LeaveOrganization` (statement `GuardNeverLeave`). An explicit Deny cannot be
overridden by any Allow, so AWS refuses the call in every account type. The call is still made, so
CloudTrail records it — with an access-denied `errorCode`. The script raises an error if the call
ever returns success, which would mean the guard was missing. Events produced (all in
**us-east-1**, because Organizations is a global service): `AssumeRole`, `DescribeOrganization`,
`LeaveOrganization` (refused). In an account that is not in an organization,
`DescribeOrganization` returns `AWSOrganizationsNotInUseException` and the leave is refused just
the same.

**Why the usual reflexes miss it.** Most detection pipelines filter CloudTrail to successful
calls to cut noise, and most real attempts are refused — by an SCP, because the caller is in the
management account (`MasterCannotLeaveOrganizationException`), or because the account is not ready
to stand alone (`ConstraintViolationException`). A success-only rule therefore sees nothing from
this emulation and almost nothing from real attackers, and the one event it would see — a success
— arrives when the organization trail has already stopped covering the account. Organizations
events are also recorded only in **us-east-1**; a pipeline that collects only workload Regions
never receives them.

**Detection thesis:** alert on every `LeaveOrganization`, regardless of `errorCode`, collected
from us-east-1. Read the `errorCode` to learn which control held, not whether to alert. Correlate a
preceding `DescribeOrganization` by the same principal — the membership check this emulation
performs, and that a deliberate actor performs too.

---

## 1. Preparation

### Prerequisites Before This Incident

**Logging & Visibility**
- **us-east-1 collection.** Organizations events, including `LeaveOrganization`, are recorded
  there regardless of the caller's Region. Confirm your trail is multi-Region or explicitly
  covers us-east-1.
- **Member-account trails as well as the organization trail.** After a successful leave the
  organization trail stops recording the account; only a trail owned by the account itself (or
  nothing) records what happens next.
- The `LeaveOrganization` event has `requestParameters: null`. `userIdentity`,
  `recipientAccountId`, `sourceIPAddress`, `userAgent` and `errorCode` are the fields to read.

**Alerting (must be pre-configured)**
- **`LeaveOrganization`, any `errorCode` → P1**; with no `errorCode` → **P0**.
- **`DescribeOrganization` followed by `LeaveOrganization` from the same principal → P1**
  (shipped as a `temporal_ordered` correlation).
- **`RemoveAccountFromOrganization` in the management account → P1** unless change-managed.

**Response Tooling**
- Management-account credentials with `organizations:DescribeAccount`, `ListAccounts`,
  `ListPoliciesForTarget`, `ListParents`.
- Member-account break-glass credentials with `iam:PutRolePolicy`, `cloudtrail:LookupEvents`.

**Known IOC Baselines**
- Nobody in a member account should ever call `LeaveOrganization`. Account migrations are done by
  named administrators and announced.

---

## 2. Identification

### Detection Triggers (prioritized)

#### HIGH-CONFIDENCE — Always Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P0 | `LeaveOrganization` with no `errorCode` | CloudTrail (us-east-1, member account) | T1666 |
| P1 | `LeaveOrganization` refused with an access-denied code (SCP or IAM deny held) | CloudTrail (us-east-1) | T1666 |
| P1 | `DescribeOrganization` then `LeaveOrganization` by one principal within 1h | CloudTrail, correlation | T1666 |
| P1 | `RemoveAccountFromOrganization` not on a change ticket | CloudTrail (management account) | T1666 |

#### MEDIUM-CONFIDENCE — May Indicate Compromise

| Priority | Event / Signal | Source | MITRE |
|----------|---------------|--------|-------|
| P2 | `LeaveOrganization` refused with `MasterCannotLeaveOrganizationException` — someone with management-account access tried it | CloudTrail (management account) | T1666 |
| P2 | `DescribeOrganization` / `ListParents` from a principal that never reads organization data | CloudTrail | T1666 |

### Detection Rule Quality Notes

| Issue | Impact | Correction |
|-------|--------|-----------|
| A success filter would make the rule blind to this emulation and to every SCP-refused attempt | The only attempts left visible are the ones that already worked | Kept the generated rule's no-filter design and documented why in the rule |
| The outcome was not interpreted | A refusal by an SCP and a refusal because the account is the management account are different findings | The KQL classifies each `errorCode` into the control that held |
| No sequence context | A lone attempt from a misfired script looks like a deliberate one | `DescribeOrganization` base rule plus a `temporal_ordered` correlation; the KQL also counts the principal's activity in the hour after |
| Management-account removal not covered | The same outcome initiated from the other side was invisible | Second document on `RemoveAccountFromOrganization` |

### Key Investigation Queries

> Organizations events are in **us-east-1**. Run these with `--region us-east-1` in the member
> account (or the management account where noted).

#### Query 1 — Every leave attempt in the last 30 days

```bash
aws cloudtrail lookup-events --region us-east-1 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=LeaveOrganization \
  --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,Username,CloudTrailEvent]' --output json
```

For each event record `userIdentity.arn`, `userIdentity.accessKeyId`, `sourceIPAddress`,
`userAgent` and `errorCode`. An access-denied code means an SCP or IAM Deny held (for this
emulation, the role's own `GuardNeverLeave` Deny). No `errorCode` means the account left — go to
§3 Step 1 now. An empty result is not proof of no attempt: check that you queried us-east-1.

#### Query 2 — Is the account still a member? (from the management account)

```bash
ACCOUNT_ID="<member-account-id>"
aws organizations describe-account --account-id "$ACCOUNT_ID"
```

`Status: ACTIVE` with the expected `JoinedTimestamp` means it is still a member.
`AccountNotFoundException` means it is no longer in the organization.

#### Query 3 — Which SCPs apply to the account (from the management account)

```bash
ACCOUNT_ID="<member-account-id>"
aws organizations list-policies-for-target --target-id "$ACCOUNT_ID" --filter SERVICE_CONTROL_POLICY
```

Repeat with the account's parent OU (`aws organizations list-parents --child-id <id>`) — SCPs
attached to OUs and the root apply too. The deny-leave SCP should appear somewhere on that path.

#### Query 4 — The principal's activity around the attempt

```bash
SESSION="<session-name-or-user-from-Query-1>"
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue="$SESSION" \
  --start-time "$(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'Events[].[EventTime,EventSource,EventName]' --output table
```

Run it in us-east-1 and in each workload Region. For an assumed role `Username` is the session name
(`atomic-t1666-org-leave` for this emulation). A `DescribeOrganization` right before the attempt is
the membership check. What the principal does after a refused attempt matters most: an actor who
failed to escape the SCPs will try to work inside them, or to disable the services they feed
(`StopLogging`, `DeleteDetector`, `DisableSecurityHub`).

---

## 3. Containment

### Immediate Actions (first 15 minutes)

#### Step 1 — If the account left: re-establish control

Invite the account back from the management account (`aws organizations invite-account-to-organization
--target Id=<account-id>,Type=ACCOUNT`) and use any credentials you still hold inside it to
contain the principal. Until the invitation is accepted, the account is outside every SCP and the
organization trail; its own trails (if any) are the only record.

#### Step 2 — Contain the principal (member account)

```bash
ROLE="<role-name-from-Query-1>"
CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
aws iam put-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"'"$CUTOFF"'"}}}]}'
```

For an IAM user, deactivate its access keys (`aws iam update-access-key --status Inactive`).
Trace the session to its source identity (`AssumeRole` events for the role ARN) and contain that too.

#### Step 3 — Make the refusal structural

Attach the deny-leave SCP to the account's OU if Query 3 did not find it. A refusal that came only
from the principal's own IAM policy — as in this emulation — is not a control the organization
owns; the next principal may not have that Deny.

---

## 4. Eradication

### Remove Attacker Access

- Rotate every credential the principal held; review the roles it could assume.

### Prevent recurrence

- Attach **`Deny-member-accounts-from-leaving-your-AWS-organization`** from the guardrail
  catalogue at the organization root. It denies `organizations:LeaveOrganization` with no
  condition, so it blocks every member account; it does not apply to the management account, which
  cannot leave in any case.
- Keep account migrations as a management-account procedure that detaches the SCP for the one
  account deliberately.

### Remove the emergency policies once clean

```bash
ROLE="<role-name-from-Query-1>"
aws iam delete-role-policy --role-name "$ROLE" --policy-name EmergencyRevokeSessions
aws iam list-role-policies --role-name "$ROLE"
```

---

## 5. Recovery

### Restore Clean State

#### Confirm membership and SCP coverage (from the management account)

```bash
ACCOUNT_ID="<member-account-id>"
aws organizations describe-account --account-id "$ACCOUNT_ID"
```

`Status: ACTIVE`, and Query 3 lists the deny-leave SCP on the account's path. If the account left
and rejoined, confirm the organization trail is recording it again and that delegated GuardDuty and
Security Hub list it as a member.

#### Confirm the corrected detection fires

```text
MUST fire on:     LeaveOrganization / organizations.amazonaws.com, with OR without errorCode
                  -> high. DescribeOrganization then LeaveOrganization by one principal within
                  1h -> high (correlation). RemoveAccountFromOrganization -> high.
MUST NOT fire on: DescribeOrganization or ListAccounts alone.
EXPECTED FP:      a planned migration between organizations, run by a named admin role.
```

Running this emulation is the test: one refused `LeaveOrganization` from session
`atomic-t1666-org-leave` in us-east-1, preceded by `DescribeOrganization`. If your rule does not
fire, check first whether it filters on `errorCode`, then whether us-east-1 is collected.

---

## 6. Lessons Learned

### Root Cause Analysis

| Finding | Contributing Control Failure |
|---------|------------------------------|
| A member-account principal could attempt to leave | `organizations:LeaveOrganization` reachable via a broad policy (`*` or `organizations:*`) |
| The attempt was refused only by the principal's own policy (this emulation) | No organization-owned SCP; the refusal depended on IAM in the account being attacked |
| The attempt was not alerted | Success-only filtering, or us-east-1 not collected |

### Recommended Guardrails

- **Catalogue match:** `Deny-member-accounts-from-leaving-your-AWS-organization` (SCP,
  unconditional deny of `organizations:LeaveOrganization`) — matches this emulation's action and
  would refuse it with no condition to evaluate.

### Technique Reference

| Type | Value |
|------|-------|
| MITRE technique | T1666 — Modify Cloud Resource Hierarchy |
| Primary API | `organizations:LeaveOrganization` (no request parameters) |
| Recon API in this emulation | `organizations:DescribeOrganization` |
| Event source / Region | `organizations.amazonaws.com`, recorded in **us-east-1** |
| Refusal codes | Access-denied (`AccessDenied` in Stratus's sample event, `AccessDeniedException` per the API reference), `MasterCannotLeaveOrganizationException`, `AWSOrganizationsNotInUseException`, `ConstraintViolationException` |
| Safety guard | Explicit IAM Deny `GuardNeverLeave` on the lab role — the call always fails |
| Lab identity | Role `stratus-red-team-org-leave-attacker-role`, session `atomic-t1666-org-leave` |

### Residual Risk

A refused attempt leaves the account inside the organization, but it tells you a principal with
enough access to try is hostile and knows where the organization's controls come from. If the
refusal came only from IAM inside the account rather than from an SCP, a principal with
`iam:*` in that account can remove the Deny and try again; only the SCP closes that path.
