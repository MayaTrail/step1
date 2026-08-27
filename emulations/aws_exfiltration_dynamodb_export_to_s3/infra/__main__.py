import base64
import json
import pathlib
import random
import uuid

import pulumi
import pulumi_aws as aws

# =========================================================================== #
# Resource Name Constants -- loaded from resource_names.json when present;    #
# falls back to inline literals so the backend (which copies only this file   #
# and Pulumi.yaml into the run dir) can still deploy without the sibling file.#
# =========================================================================== #
_P = pathlib.Path(__file__).parent / "resource_names.json"
if _P.exists():
    _NAMES = json.loads(_P.read_text())
else:
    _NAMES = {
        "resources": {
            "prod_customers_table":    "prod-customers",
            "internal_api_keys_table": "internal-api-keys",
            "victim_role":             "atomic-dynamodb-export-to-s3-victim-role",
            "victim_policy":           "atomic-dynamodb-export-to-s3-victim-policy",
            "attacker_user":           "atomic-dynamodb-export-to-s3-attacker-user",
        }
    }
_R = _NAMES["resources"]

PROD_CUSTOMERS_TABLE_NAME    = _R["prod_customers_table"]
INTERNAL_API_KEYS_TABLE_NAME = _R["internal_api_keys_table"]
VICTIM_ROLE_NAME             = _R["victim_role"]
VICTIM_POLICY_NAME           = _R["victim_policy"]
ATTACKER_USER_NAME           = _R["attacker_user"]

# Account identity resolved at deploy time
identity   = aws.get_caller_identity()
account_id = identity.account_id

TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-dynamodb-export-to-s3",
    "Technique":   "T1530",
}

# =========================================================================== #
# Seeded synthetic data helpers (stdlib only -- no Faker in backend image)    #
# Seed=42 makes UUIDs stable across re-runs so TableItems are not replaced.  #
# =========================================================================== #
_rng = random.Random(42)

_FIRST = ["James", "Mary", "Robert", "Patricia", "John", "Jennifer",
          "Michael", "Linda", "David", "Barbara", "William", "Susan"]
_LAST  = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
          "Miller", "Davis", "Wilson", "Taylor", "Anderson", "Thomas"]
_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
            "protonmail.com", "icloud.com", "example.com", "corp.net"]


def _uuid() -> str:
    return str(uuid.UUID(int=_rng.getrandbits(128)))


def _email(first: str, last: str) -> str:
    return f"{first.lower()}.{last.lower()}{_rng.randint(1, 999)}@{_rng.choice(_DOMAINS)}"


def _ssn() -> str:
    return f"{_rng.randint(100, 999)}-{_rng.randint(10, 99)}-{_rng.randint(1000, 9999)}"


def _cc_last4() -> str:
    return str(_rng.randint(1000, 9999))


def _hex32() -> str:
    return "".join(f"{_rng.randint(0, 255):02x}" for _ in range(16))


def _b64_44() -> str:
    raw = bytes(_rng.randint(0, 255) for _ in range(33))
    return base64.b64encode(raw).decode("ascii")[:44]


# =========================================================================== #
# 1. prod-customers DynamoDB table (target)                                    #
# PITR enabled -- required for ExportTableToPointInTime.                      #
# Only the hash key appears in attributes; non-key fields cause ValidationErr.#
# SSE omitted -- AWS applies an AWS-owned key by default; CMK requires extra  #
# key-policy grants for the export service path that fail silently.           #
# =========================================================================== #
prod_customers_table = aws.dynamodb.Table(
    "prod-customers-table",
    name=PROD_CUSTOMERS_TABLE_NAME,
    billing_mode="PAY_PER_REQUEST",
    hash_key="customer_id",
    attributes=[
        aws.dynamodb.TableAttributeArgs(name="customer_id", type="S"),
    ],
    point_in_time_recovery=aws.dynamodb.TablePointInTimeRecoveryArgs(enabled=True),
    tags=TAGS,
)

# =========================================================================== #
# 2. Seed prod-customers with 12 synthetic PII records (support)               #
# =========================================================================== #
for _i in range(12):
    _first = _FIRST[_i]
    _last  = _LAST[_i]
    aws.dynamodb.TableItem(
        f"prod-customers-seed-{_i}",
        table_name=prod_customers_table.name,
        hash_key="customer_id",
        item=json.dumps({
            "customer_id":       {"S": _uuid()},
            "email":             {"S": _email(_first, _last)},
            "full_name":         {"S": f"{_first} {_last}"},
            "ssn":               {"S": _ssn()},
            "credit_card_last4": {"S": _cc_last4()},
        }),
    )

# =========================================================================== #
# 3. internal-api-keys honey table (bait)                                      #
# PITR intentionally NOT enabled -- ExportTableToPointInTime raises            #
# ContinuousBackupsUnavailableException; realistic friction for the attacker. #
# =========================================================================== #
internal_api_keys_table = aws.dynamodb.Table(
    "internal-api-keys-table",
    name=INTERNAL_API_KEYS_TABLE_NAME,
    billing_mode="PAY_PER_REQUEST",
    hash_key="service_name",
    attributes=[
        aws.dynamodb.TableAttributeArgs(name="service_name", type="S"),
    ],
    tags=TAGS,
)

# =========================================================================== #
# 4. Seed internal-api-keys with 8 plausible fake credential records (support) #
# =========================================================================== #
_SERVICE_NAMES = [
    "stripe-prod", "twilio", "sendgrid", "datadog",
    "pagerduty", "github-actions", "slack-webhook", "aws-backup",
]
_TEAM_NAMES = [
    "platform-eng", "data-eng", "security", "devops",
    "backend", "mobile", "ml-ops", "sre",
]
for _i, _svc in enumerate(_SERVICE_NAMES):
    aws.dynamodb.TableItem(
        f"internal-api-keys-seed-{_i}",
        table_name=internal_api_keys_table.name,
        hash_key="service_name",
        item=json.dumps({
            "service_name": {"S": _svc},
            "api_key":      {"S": _hex32()},
            "secret":       {"S": _b64_44()},
            "owner":        {"S": _TEAM_NAMES[_i]},
        }),
    )

# =========================================================================== #
# 5. Export S3 bucket (target)                                                  #
# Name suffixed with account_id for global uniqueness.                        #
# force_destroy=True: DynamoDB export writes objects; destroy must empty it.  #
# Versioning not enabled -- compounds cleanup and adds no emulation value.    #
# Companion resources are separate per pulumi-aws v7 (no inline args on BucketV2).
# =========================================================================== #
export_bucket = aws.s3.BucketV2(
    "export-bucket",
    bucket=f"prod-dynamodb-exports-{account_id}",
    force_destroy=True,
    tags=TAGS,
)

# 5a. Block all public access
aws.s3.BucketPublicAccessBlock(
    "export-bucket-pab",
    bucket=export_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
)

# 5b. BucketOwnerEnforced disables legacy ACLs; s3:PutObjectAcl in the victim
# policy is granted at IAM layer but never evaluated at the object layer --
# this matches the documented DynamoDB export requirement without enabling ACL mode.
aws.s3.BucketOwnershipControls(
    "export-bucket-ownership",
    bucket=export_bucket.id,
    rule=aws.s3.BucketOwnershipControlsRuleArgs(
        object_ownership="BucketOwnerEnforced",
    ),
)

# 5c. AES256 SSE -- no CMK; CMK requires extra key-policy grants that fail silently
aws.s3.BucketServerSideEncryptionConfigurationV2(
    "export-bucket-sse",
    bucket=export_bucket.id,
    rules=[
        aws.s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
            apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
                sse_algorithm="AES256",
            ),
        )
    ],
)

# =========================================================================== #
# 6. Victim IAM Role (attack_surface)                                           #
# Trust principal: current account root -- safe self-trust, no external       #
# backdoor. Constraint 3: never use a placeholder or external account ID.     #
# =========================================================================== #
victim_role = aws.iam.Role(
    "victim-role",
    name=VICTIM_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }),
    tags=TAGS,
)

# =========================================================================== #
# 7. Victim inline policy (attack_surface)                                      #
# Built from Output references -- no region or account ID hardcoding.         #
# DynamoDBRecon on Resource:"*": ListTables/DescribeTable are account-level   #
# APIs; table ARNs are invalid targets for them.                              #
# DescribeContinuousBackups granted so the PITR gate can be checked under     #
# victim credentials without AccessDenied.                                    #
# s3:GetObject included: required for HeadObject + manifest reads post-export.#
# _note keys from the approved plan are stripped -- they cause MalformedPolicyDocument.
# =========================================================================== #
victim_policy_doc = pulumi.Output.all(
    prod_customers_table.arn,
    export_bucket.arn,
).apply(lambda args: json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DynamoDBRecon",
            "Effect": "Allow",
            "Action": [
                "dynamodb:ListTables",
                "dynamodb:DescribeTable",
                "dynamodb:DescribeContinuousBackups",
            ],
            "Resource": "*",
        },
        {
            "Sid": "DynamoDBExport",
            "Effect": "Allow",
            "Action": [
                "dynamodb:ExportTableToPointInTime",
                "dynamodb:DescribeExport",
                "dynamodb:ListExports",
            ],
            "Resource": [
                args[0],
                args[0] + "/export/*",
            ],
        },
        {
            "Sid": "S3BucketLevel",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetBucketLocation",
            ],
            "Resource": args[1],
        },
        {
            "Sid": "S3ObjectLevel",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:PutObjectAcl",
                "s3:AbortMultipartUpload",
                "s3:ListMultipartUploadParts",
                "s3:GetObject",
            ],
            "Resource": args[1] + "/*",
        },
    ],
}))

aws.iam.RolePolicy(
    "victim-policy",
    name=VICTIM_POLICY_NAME,
    role=victim_role.id,
    policy=victim_policy_doc,
)

# =========================================================================== #
# 8. Attacker IAM identity (attack_surface)                                     #
# A static access key modelling the compromised/leaked credential the attack   #
# starts from. It holds no direct data-plane rights of its own -- only         #
# sts:AssumeRole on victim_role, matching attack.py's Phase 1 credential       #
# chain (attacker static IAM key -> AssumeRole -> victim_role_boto3_session).  #
# victim_role's trust policy already allows any principal in this account     #
# with sts:AssumeRole permission (Principal: account root), so no trust-policy #
# change is needed here -- only granting this user the AssumeRole action.      #
# =========================================================================== #
attacker_user = aws.iam.User(
    "attacker-user",
    name=ATTACKER_USER_NAME,
    tags=TAGS,
)

attacker_access_key = aws.iam.AccessKey(
    "attacker-access-key",
    user=attacker_user.name,
)

aws.iam.UserPolicy(
    "attacker-policy",
    name=f"{ATTACKER_USER_NAME}-assume-victim-role",
    user=attacker_user.name,
    policy=victim_role.arn.apply(lambda arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": arn,
            }
        ],
    })),
)

# =========================================================================== #
# Pulumi exports -- keys must match pulumi_export_keys in resource_names.json  #
# attack.py reads these via run(outputs, region)                               #
# =========================================================================== #
pulumi.export("victim_role_arn",              victim_role.arn)
pulumi.export("victim_role_name",             victim_role.name)
pulumi.export("export_bucket_name",           export_bucket.id)
pulumi.export("sink_bucket_name",             export_bucket.id)  # alias: attack.py's own name for the export sink
pulumi.export("prod_customers_table_name",    prod_customers_table.name)
pulumi.export("prod_customers_table_arn",     prod_customers_table.arn)
pulumi.export("attacker_access_key_id",       attacker_access_key.id)
pulumi.export("attacker_secret_access_key",   pulumi.Output.secret(attacker_access_key.secret))
pulumi.export("internal_api_keys_table_name", internal_api_keys_table.name)
