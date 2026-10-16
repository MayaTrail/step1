# Detection Note: T1666 (Attempt to Leave the AWS Organization)

**Signal:** `organizations:LeaveOrganization` (`eventSource: organizations.amazonaws.com`, recorded in **us-east-1** because Organizations is global), **including** events with an access-denied `errorCode`. The call takes no parameters; the principal (`userIdentity.arn`) and the account (`recipientAccountId`) are the whole signal.

**Safety design of this emulation:** the lab role `stratus-red-team-org-leave-attacker-role` has `organizations:DescribeOrganization` allowed and an **explicit IAM Deny** on `organizations:LeaveOrganization`. The call is really made, so CloudTrail records it, but AWS always refuses it. The account cannot leave. Any detection that filters out events with an `errorCode` will never see this emulation — and will also miss every real attempt that an SCP refused.

## What ships

| Rule | Level | Fires on the emulation |
|------|-------|------------------------|
| `organizations_leave_attempt` - any LeaveOrganization | high | yes (refused) |
| RemoveAccountFromOrganization (management-account side) | high | no |
| `organizations_describe_bb` - DescribeOrganization (base rule) | informational | yes (sequence component only) |
| DescribeOrganization then LeaveOrganization by one principal within 1h (`temporal_ordered`) | high | yes |

The KQL classifies each attempt by which control refused it (`AccessDenied*`, `MasterCannotLeaveOrganizationException`, `AWSOrganizationsNotInUseException`, `ConstraintViolationException`) and counts the principal's reconnaissance before and activity after.

## Coverage beyond the rule

- The **`Deny-member-accounts-from-leaving-your-AWS-organization`** SCP in the guardrail catalogue denies `organizations:LeaveOrganization` unconditionally. SCPs do not apply to the management account, which cannot leave anyway.
- GuardDuty has no finding type dedicated to this call.
- A successful leave is visible from the management account as the member disappearing from `ListAccounts`; the member's own events go to its own trails from then on, not the organization trail.

## Response

1. From the management account, confirm the account is still a member (`aws organizations describe-account --account-id <id>`).
2. Verify the deny-leave SCP is attached to the account's OU.
3. Treat the principal as compromised: an actor trying to leave is about to do something the organization's controls would catch.

**MITRE:** T1666 (*Modify Cloud Resource Hierarchy*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** session `atomic-t1666-org-leave` on `stratus-red-team-org-leave-attacker-role`; `DescribeOrganization` then a refused `LeaveOrganization`, both in us-east-1.
