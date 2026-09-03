import json
import pathlib

import pulumi
import pulumi_aws as aws

# ── Resource Name Registry ──────────────────────────────────────────────────
# Loaded from resource_names.json when present (local dev); falls back to inline
# literals so the backend — which copies only Pulumi.yaml + __main__.py into the
# run dir — can still deploy without the sibling file.
_P = pathlib.Path(__file__).parent / "resource_names.json"
if _P.exists():
    _R = json.loads(_P.read_text())["resources"]
else:
    _R = {
        "codecommit_repo_name":       "prod-build-service",
        "canary_secret_name":         "prod/build-service/db-master-credentials",
        "pipeline_service_role_name": "codepipeline-inject-stage-pipeline-svc-role",
        "build_service_role_name":    "codepipeline-inject-stage-build-svc-role",
        "victim_role_name":           "codepipeline-inject-stage-victim-role",
        "victim_user_name":           "codepipeline-inject-stage-victim-user",
        "build_project_name":         "atomic-codepipeline-inject-stage-build",
        "pipeline_name":              "atomic-codepipeline-inject-stage-prod-deploy",
    }

CODECOMMIT_REPO_NAME       = _R["codecommit_repo_name"]
CANARY_SECRET_NAME         = _R["canary_secret_name"]
PIPELINE_SERVICE_ROLE_NAME = _R["pipeline_service_role_name"]
BUILD_SERVICE_ROLE_NAME    = _R["build_service_role_name"]
VICTIM_ROLE_NAME           = _R["victim_role_name"]
VICTIM_USER_NAME           = _R["victim_user_name"]
BUILD_PROJECT_NAME         = _R["build_project_name"]
PIPELINE_NAME              = _R["pipeline_name"]

# ── Caller Identity ───────────────────────────────────────────────────────────
identity   = aws.get_caller_identity()
account_id = identity.account_id

# Artifact bucket name embeds account_id for global uniqueness
ARTIFACT_BUCKET_NAME = f"codepipeline-inject-stage-artifacts-{account_id}"

TAGS = {
    "MayaTrail":   "true",
    "Purpose":     "adversary-emulation",
    "ThreatActor": "ATOMIC-codepipeline-inject-stage",
    "Technique":   "T1195",
}

# ══════════════════════════════════════════════════════════════════════════════
# 1. Artifact Bucket  (CodePipeline inter-stage artifact store)
# ══════════════════════════════════════════════════════════════════════════════
artifact_bucket = aws.s3.BucketV2(
    "artifact-bucket",
    bucket=ARTIFACT_BUCKET_NAME,
    force_destroy=True,
    tags=TAGS,
)

# Pipeline stages version artifacts — versioning required
aws.s3.BucketVersioningV2(
    "artifact-bucket-versioning",
    bucket=artifact_bucket.id,
    versioning_configuration=aws.s3.BucketVersioningV2VersioningConfigurationArgs(
        status="Enabled",
    ),
    opts=pulumi.ResourceOptions(depends_on=[artifact_bucket]),
)

aws.s3.BucketServerSideEncryptionConfigurationV2(
    "artifact-bucket-sse",
    bucket=artifact_bucket.id,
    rules=[
        aws.s3.BucketServerSideEncryptionConfigurationV2RuleArgs(
            apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationV2RuleApplyServerSideEncryptionByDefaultArgs(
                sse_algorithm="AES256",
            ),
        )
    ],
    opts=pulumi.ResourceOptions(depends_on=[artifact_bucket]),
)

aws.s3.BucketPublicAccessBlock(
    "artifact-bucket-pab",
    bucket=artifact_bucket.id,
    block_public_acls=True,
    block_public_policy=True,
    ignore_public_acls=True,
    restrict_public_buckets=True,
    opts=pulumi.ResourceOptions(depends_on=[artifact_bucket]),
)

# ══════════════════════════════════════════════════════════════════════════════
# 2. CodeCommit Repository  (bait source repo)
# ══════════════════════════════════════════════════════════════════════════════
# Post-provision step (documented in attack.py): seed branch 'main' with a
# buildspec.yml referencing the canary secret via PutFile API.
codecommit_repo = aws.codecommit.Repository(
    "codecommit-repo",
    repository_name=CODECOMMIT_REPO_NAME,
    description="Application build and deploy service",
    tags=TAGS,
)

# ══════════════════════════════════════════════════════════════════════════════
# 3. Canary Secret  (bait production credential)
# ══════════════════════════════════════════════════════════════════════════════
canary_secret = aws.secretsmanager.Secret(
    "canary-secret",
    name=CANARY_SECRET_NAME,
    recovery_window_in_days=0,
    tags={**TAGS, "Environment": "production", "Team": "data"},
)

aws.secretsmanager.SecretVersion(
    "canary-secret-version",
    secret_id=canary_secret.id,
    secret_string=json.dumps({
        "username": "dbadmin",
        "password": "Pr0dMasterKey#2024!zQ",
        "host":     "prod-db-cluster.cluster-cxyz1234abcd.us-east-1.rds.amazonaws.com",
        "port":     5432,
        "dbname":   "production",
    }),
    opts=pulumi.ResourceOptions(depends_on=[canary_secret]),
)

# ══════════════════════════════════════════════════════════════════════════════
# 4. Pipeline Service Role
#    codebuild:StartBuild on * is the key misconfiguration — any injected stage
#    referencing an existing project name executes without further IAM changes.
# ══════════════════════════════════════════════════════════════════════════════
pipeline_service_role = aws.iam.Role(
    "pipeline-service-role",
    name=PIPELINE_SERVICE_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"Service": "codepipeline.amazonaws.com"},
            "Action":    "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

aws.iam.RolePolicy(
    "pipeline-service-role-policy",
    role=pipeline_service_role.id,
    policy=pulumi.Output.all(artifact_bucket.arn, codecommit_repo.arn).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid":      "CodeBuildBroadAccess",
                    "Effect":   "Allow",
                    "Action":   ["codebuild:StartBuild", "codebuild:BatchGetBuilds"],
                    "Resource": "*",
                },
                {
                    "Sid":    "ArtifactBucketAccess",
                    "Effect": "Allow",
                    "Action": [
                        "s3:PutObject",
                        "s3:GetObject",
                        "s3:GetObjectVersion",
                        "s3:GetBucketVersioning",
                    ],
                    "Resource": [args[0], f"{args[0]}/*"],
                },
                {
                    "Sid":    "CodeCommitAccess",
                    "Effect": "Allow",
                    "Action": [
                        "codecommit:GetBranch",
                        "codecommit:GetCommit",
                        "codecommit:UploadArchive",
                        "codecommit:GetUploadArchiveStatus",
                    ],
                    "Resource": args[1],
                },
            ],
        })
    ),
    opts=pulumi.ResourceOptions(depends_on=[pipeline_service_role]),
)

# ══════════════════════════════════════════════════════════════════════════════
# 5. Build Service Role
#    Includes secretsmanager:GetSecretValue on the canary secret — demonstrates
#    blast radius of an injected stage that runs as this role.
# ══════════════════════════════════════════════════════════════════════════════
build_service_role = aws.iam.Role(
    "build-service-role",
    name=BUILD_SERVICE_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action":    "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

aws.iam.RolePolicy(
    "build-service-role-policy",
    role=build_service_role.id,
    policy=pulumi.Output.all(
        artifact_bucket.arn,
        codecommit_repo.arn,
        canary_secret.arn,
    ).apply(lambda args: json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid":      "CloudWatchLogs",
                "Effect":   "Allow",
                "Action":   [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            },
            {
                "Sid":    "ArtifactBucketAccess",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:GetObjectVersion",
                    "s3:GetBucketVersioning",
                ],
                "Resource": [args[0], f"{args[0]}/*"],
            },
            {
                "Sid":      "CodeCommitPull",
                "Effect":   "Allow",
                "Action":   ["codecommit:GitPull"],
                "Resource": args[1],
            },
            {
                "Sid":      "CanarySecretRead",
                "Effect":   "Allow",
                "Action":   ["secretsmanager:GetSecretValue"],
                "Resource": args[2],
            },
        ],
    })),
    opts=pulumi.ResourceOptions(depends_on=[build_service_role]),
)

# ══════════════════════════════════════════════════════════════════════════════
# 6. Victim Role  (compromised CICD service account — attack entry point)
#    Trust: current account root so the victim user (or lab operator) can
#    assume it; attack.py calls sts:AssumeRole to obtain scoped session.
# ══════════════════════════════════════════════════════════════════════════════
victim_role = aws.iam.Role(
    "victim-role",
    name=VICTIM_ROLE_NAME,
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":    "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action":    "sts:AssumeRole",
        }],
    }),
    tags=TAGS,
)

# ══════════════════════════════════════════════════════════════════════════════
# 7. Victim IAM User + Access Key  (leaked CICD service account credential)
# ══════════════════════════════════════════════════════════════════════════════
victim_user = aws.iam.User(
    "victim-user",
    name=VICTIM_USER_NAME,
    path="/",
    tags=TAGS,
)

aws.iam.UserPolicy(
    "victim-user-assume-role-policy",
    user=victim_user.name,
    policy=victim_role.arn.apply(lambda arn: json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":   "Allow",
            "Action":   "sts:AssumeRole",
            "Resource": arn,
        }],
    })),
    opts=pulumi.ResourceOptions(depends_on=[victim_user, victim_role]),
)

victim_access_key = aws.iam.AccessKey(
    "victim-access-key",
    user=victim_user.name,
    opts=pulumi.ResourceOptions(depends_on=[victim_user]),
)

# ══════════════════════════════════════════════════════════════════════════════
# 8. CodeBuild Project  (legitimate build target; attacker reuses its name)
#    Attacker's UpdatePipeline inserts a new stage referencing this same
#    ProjectName — no codebuild:CreateProject required in victim policy.
# ══════════════════════════════════════════════════════════════════════════════
BUILDSPEC = (
    "version: 0.2\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    "      - echo BUILD_PHASE_EXECUTED\n"
)

build_project = aws.codebuild.Project(
    "build-project",
    name=BUILD_PROJECT_NAME,
    service_role=build_service_role.arn,
    source=aws.codebuild.ProjectSourceArgs(
        type="CODEPIPELINE",
        buildspec=BUILDSPEC,
    ),
    environment=aws.codebuild.ProjectEnvironmentArgs(
        type="LINUX_CONTAINER",
        compute_type="BUILD_GENERAL1_SMALL",
        image="aws/codebuild/standard:7.0",
    ),
    artifacts=aws.codebuild.ProjectArtifactsArgs(
        type="CODEPIPELINE",
    ),
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[build_service_role, artifact_bucket]),
)

# ══════════════════════════════════════════════════════════════════════════════
# 9. CodePipeline  (target pipeline for T1195 stage injection)
#    V1 default: no execution_mode or pipeline_type set.
#    The attacker calls GetPipeline, splices in 'AttackerStage' at index 1
#    (between Source and Build), then calls UpdatePipeline.
# ══════════════════════════════════════════════════════════════════════════════
pipeline = aws.codepipeline.Pipeline(
    "pipeline",
    name=PIPELINE_NAME,
    role_arn=pipeline_service_role.arn,
    artifact_stores=[
        aws.codepipeline.PipelineArtifactStoreArgs(
            type="S3",
            location=artifact_bucket.id,
        )
    ],
    stages=[
        aws.codepipeline.PipelineStageArgs(
            name="Source",
            actions=[
                aws.codepipeline.PipelineStageActionArgs(
                    name="SourceAction",
                    category="Source",
                    owner="AWS",
                    provider="CodeCommit",
                    version="1",
                    configuration={
                        "RepositoryName":       CODECOMMIT_REPO_NAME,
                        "BranchName":           "main",
                        "PollForSourceChanges": "true",
                    },
                    output_artifacts=["SourceArtifact"],
                    run_order=1,
                )
            ],
        ),
        aws.codepipeline.PipelineStageArgs(
            name="Build",
            actions=[
                aws.codepipeline.PipelineStageActionArgs(
                    name="BuildAction",
                    category="Build",
                    owner="AWS",
                    provider="CodeBuild",
                    version="1",
                    configuration={
                        "ProjectName": BUILD_PROJECT_NAME,
                    },
                    input_artifacts=["SourceArtifact"],
                    output_artifacts=["BuildArtifact"],
                    run_order=1,
                )
            ],
        ),
    ],
    tags=TAGS,
    opts=pulumi.ResourceOptions(depends_on=[
        artifact_bucket,
        codecommit_repo,
        pipeline_service_role,
        build_project,
    ]),
)

# ══════════════════════════════════════════════════════════════════════════════
# 10. Victim Role Policy  (created last — depends on pipeline ARN)
#     Minimum two-call set for T1195 plus execution/observation calls attack.py
#     uses to verify the injected stage ran.
#     ListPipelines has no resource-level scoping — must use Resource: *.
# ══════════════════════════════════════════════════════════════════════════════
aws.iam.RolePolicy(
    "victim-role-policy",
    name="codepipeline-inject-stage-victim-role-policy",
    role=victim_role.id,
    policy=pulumi.Output.all(pipeline.arn, pipeline_service_role.arn).apply(
        lambda args: json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid":      "PipelineInjection",
                    "Effect":   "Allow",
                    "Action":   [
                        "codepipeline:GetPipeline",
                        "codepipeline:UpdatePipeline",
                    ],
                    # UpdatePipeline is authorized against the pipeline ARN *and*
                    # the per-stage sub-resources (arn/<stage>), so both are needed.
                    "Resource": [args[0], args[0] + "/*"],
                },
                {
                    # UpdatePipeline re-submits the full definition, which names the
                    # pipeline service role -> the caller needs iam:PassRole for it.
                    "Sid":      "PassPipelineServiceRole",
                    "Effect":   "Allow",
                    "Action":   "iam:PassRole",
                    "Resource": args[1],
                    "Condition": {
                        "StringEquals": {"iam:PassedToService": "codepipeline.amazonaws.com"}
                    },
                },
                {
                    "Sid":      "PipelineExecutionAndObservation",
                    "Effect":   "Allow",
                    "Action":   [
                        "codepipeline:StartPipelineExecution",
                        "codepipeline:GetPipelineState",
                        "codepipeline:ListPipelineExecutions",
                    ],
                    "Resource": args[0],
                },
                {
                    "Sid":      "PipelineEnumeration",
                    "Effect":   "Allow",
                    "Action":   ["codepipeline:ListPipelines"],
                    "Resource": "*",
                },
            ],
        })
    ),
    opts=pulumi.ResourceOptions(depends_on=[victim_role, pipeline]),
)

# ══════════════════════════════════════════════════════════════════════════════
# Pulumi Exports  (keys match pulumi_export_keys in resource_names.json)
# ══════════════════════════════════════════════════════════════════════════════
pulumi.export("artifact_bucket_name",           artifact_bucket.id)
pulumi.export("codecommit_repo_name",           CODECOMMIT_REPO_NAME)
pulumi.export("codecommit_repo_clone_url_http", codecommit_repo.clone_url_http)
pulumi.export("canary_secret_arn",              canary_secret.arn)
pulumi.export("pipeline_service_role_arn",      pipeline_service_role.arn)
pulumi.export("build_service_role_arn",         build_service_role.arn)
pulumi.export("victim_role_arn",                victim_role.arn)
pulumi.export("victim_role_name",               VICTIM_ROLE_NAME)
pulumi.export("build_project_name",             BUILD_PROJECT_NAME)
pulumi.export("pipeline_arn",                   pipeline.arn)
pulumi.export("pipeline_name",                  PIPELINE_NAME)
pulumi.export("victim_access_key_id",           victim_access_key.id)
pulumi.export("victim_secret_access_key",       pulumi.Output.secret(victim_access_key.secret))
