import json
import pathlib
import pulumi
import pulumi_aws as aws

# ---------------------------------------------------------------------------
# Resource Name Constants (single source of truth: resource_names.json)
# ---------------------------------------------------------------------------
_NAMES = {'campaign': 'ATOMIC-iam-delete-entities',
 'csp': 'aws',
 'resources': {'backdoor_user_name': 'svc-prod-recovery-admin',
               'backdoor_role_name': 'OrganizationAccountAccessRole-shadow',
               'attacker_exec_role_name': 'atomic-iam-delete-attacker-exec-role'},
 'pulumi_export_keys': {'backdoor_user_name': 'backdoor_user_name',
                        'backdoor_role_name': 'backdoor_role_name',
                        'attacker_exec_role_name': 'attacker_exec_role_name',
                        'backdoor_user_arn': 'backdoor_user_arn',
                        'backdoor_role_arn': 'backdoor_role_arn',
                        'attacker_exec_role_arn': 'attacker_exec_role_arn',
                        'backdoor_user_key_id': 'backdoor_user_key_id',
                        'backdoor_user_key_secret': 'backdoor_user_key_secret'}}
_R = _NAMES["resources"]

BACKDOOR_USER_NAME      = _R["backdoor_user_name"]       # svc-prod-recovery-admin
BACKDOOR_ROLE_NAME      = _R["backdoor_role_name"]       # OrganizationAccountAccessRole-shadow
ATTACKER_EXEC_ROLE_NAME = _R["attacker_exec_role_name"]  # atomic-iam-delete-attacker-exec-role

TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-iam-delete-entities",
    "Technique":   "T1070.009",
}

# ---------------------------------------------------------------------------
# Account identity (synchronous invoke - returns plain values, not Outputs)
# ---------------------------------------------------------------------------
identity   = aws.get_caller_identity()
account_id = identity.account_id

# ---------------------------------------------------------------------------
# Pre-compute deterministic ARNs to break the circular dependency:
#   backdoor_role trust policy must name the attacker exec role ARN, but
#   the exec role is created after the backdoor role.  IAM ARNs are
#   deterministic (account_id + name), so we compute them ahead of time.
# ---------------------------------------------------------------------------
backdoor_user_arn_computed      = f"arn:aws:iam::{account_id}:user/{BACKDOOR_USER_NAME}"
backdoor_role_arn_computed      = f"arn:aws:iam::{account_id}:role/{BACKDOOR_ROLE_NAME}"
attacker_exec_role_arn_computed = f"arn:aws:iam::{account_id}:role/{ATTACKER_EXEC_ROLE_NAME}"

# ---------------------------------------------------------------------------
# Trust policy: backdoor role trusts the attacker exec role (simulates a
# real cross-account backdoor pointing at the attacker-controlled identity)
# ---------------------------------------------------------------------------
backdoor_role_trust = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect":    "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},  # IAM rejects a role principal that does not exist yet
        "Action":    "sts:AssumeRole",
    }],
})

# ---------------------------------------------------------------------------
# Trust policy: attacker exec role trusts the lab operator (current account
# root).  The attack script assumes this role using the operator credentials.
# Self-trust on account root is deployable in any lab account.
# ---------------------------------------------------------------------------
attacker_exec_trust = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect":    "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
        "Action":    "sts:AssumeRole",
    }],
})

# ---------------------------------------------------------------------------
# Inline policy: strictly ARN-pinned to the two lab identity ARNs.
# Includes all prerequisite sub-actions (ListAccessKeys, DeleteAccessKey,
# ListRolePolicies, etc.) that AWS requires before DeleteUser/DeleteRole will
# succeed without DeleteConflict or EntityHasPolicy errors.
# No wildcards, no iam:* - this is the safety enforcement mechanism.
# ---------------------------------------------------------------------------
attacker_exec_policy_doc = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid":    "DeleteBackdoorUser",
            "Effect": "Allow",
            "Action": [
                "iam:DeleteUser",
                "iam:DeleteAccessKey",
                "iam:ListAccessKeys",
                "iam:DeleteLoginProfile",
                "iam:ListUserPolicies",
                "iam:ListAttachedUserPolicies",
                "iam:DetachUserPolicy",
                "iam:DeleteUserPolicy",
            ],
            "Resource": backdoor_user_arn_computed,
        },
        {
            "Sid":    "DeleteBackdoorRole",
            "Effect": "Allow",
            "Action": [
                "iam:DeleteRole",
                "iam:ListRolePolicies",
                "iam:ListAttachedRolePolicies",
                "iam:DeleteRolePolicy",
                "iam:DetachRolePolicy",
                "iam:ListInstanceProfilesForRole",
                "iam:RemoveRoleFromInstanceProfile",
            ],
            "Resource": backdoor_role_arn_computed,
        },
    ],
})

# ---------------------------------------------------------------------------
# 1. Backdoor IAM user - persistence artifact targeted by T1070.009
#
# retain_on_delete=False: Pulumi will attempt to delete on `pulumi destroy`.
# If attack.py already deleted this resource, destroy will return
# NoSuchEntity.  Operator runbook: run
#   pulumi state delete urn:...:atomic-iam-delete-backdoor-user
# to remove the orphaned state entry before re-running pulumi destroy.
# ---------------------------------------------------------------------------
backdoor_user = aws.iam.User(
    "atomic-iam-delete-backdoor-user",
    name=BACKDOOR_USER_NAME,
    path="/",
    tags=TAGS,
    opts=pulumi.ResourceOptions(retain_on_delete=False),
)

# ---------------------------------------------------------------------------
# 2. Backdoor IAM role - cross-account/federated persistence artifact
#
# Same retain_on_delete / state-delete runbook as the backdoor user above.
# ---------------------------------------------------------------------------
backdoor_role = aws.iam.Role(
    "atomic-iam-delete-backdoor-role",
    name=BACKDOOR_ROLE_NAME,
    assume_role_policy=backdoor_role_trust,
    tags=TAGS,
    opts=pulumi.ResourceOptions(retain_on_delete=False),
)

# ---------------------------------------------------------------------------
# 3. Active access key on the backdoor user
#    Proves the identity is a live credential-based persistence mechanism.
#    The emulation must call DeleteAccessKey before DeleteUser.
# ---------------------------------------------------------------------------
backdoor_user_key = aws.iam.AccessKey(
    "atomic-iam-delete-backdoor-user-key",
    user=backdoor_user.name,
    status="Active",
    opts=pulumi.ResourceOptions(depends_on=[backdoor_user]),
)

# ---------------------------------------------------------------------------
# 4. Attacker execution role
#    Holds the seeded attacker credentials; attack.py assumes this role.
# ---------------------------------------------------------------------------
attacker_exec_role = aws.iam.Role(
    "atomic-iam-delete-attacker-exec-role",
    name=ATTACKER_EXEC_ROLE_NAME,
    assume_role_policy=attacker_exec_trust,
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[backdoor_user, backdoor_role]),
)

# ---------------------------------------------------------------------------
# 5. Inline policy on the attacker exec role
#    ARN-pinned to the two lab identity ARNs - no wildcards permitted.
# ---------------------------------------------------------------------------
attacker_exec_policy = aws.iam.RolePolicy(
    "atomic-iam-delete-attacker-exec-policy",
    role=attacker_exec_role.name,
    policy=attacker_exec_policy_doc,
    opts=pulumi.ResourceOptions(depends_on=[attacker_exec_role]),
)

# ---------------------------------------------------------------------------
# Exports - all keys must match pulumi_export_keys in resource_names.json
# ---------------------------------------------------------------------------
pulumi.export("backdoor_user_name",       BACKDOOR_USER_NAME)
pulumi.export("backdoor_role_name",       BACKDOOR_ROLE_NAME)
pulumi.export("attacker_exec_role_name",  ATTACKER_EXEC_ROLE_NAME)
pulumi.export("backdoor_user_arn",        backdoor_user.arn)
pulumi.export("backdoor_role_arn",        backdoor_role.arn)
pulumi.export("attacker_exec_role_arn",   attacker_exec_role.arn)
pulumi.export("backdoor_user_key_id",     backdoor_user_key.id)
pulumi.export("backdoor_user_key_secret", backdoor_user_key.secret)
