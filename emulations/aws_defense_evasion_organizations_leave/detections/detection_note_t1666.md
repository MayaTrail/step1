# Detection Note: T1666 (Attempt to Leave the AWS Organization)

**Signal:** `organizations:LeaveOrganization`, **including** events with `errorCode = AccessDenied`. Organizations is global; the event is recorded in **us-east-1**.

## Coverage beyond the rule

- An SCP denying `organizations:LeaveOrganization` in every member account is the standard preventive control (AWS publishes it as an example SCP).
- This emulation's attempt is always denied by design. In your tenant a successful leave would also emit `AccountLeftOrganization`-type events in the management account.

## Response

1. Confirm the account is still a member (`DescribeAccount` from the management account).
2. Add or verify the deny-leave SCP.
3. Treat the principal as compromised: an attacker trying to leave is about to do something the organization's controls would catch.

**MITRE:** T1666 (*Modify Cloud Resource Hierarchy*).
**Severity:** manifest HIGH.
**Emulation fingerprint:** the run assumes the lab role `stratus-red-team-org-leave-attacker-role` (session name `atomic-*`) and, where the technique is reversible, reverts it seconds later. A real attacker leaves the change in place; the pairing is not a reason to downgrade the alert.
