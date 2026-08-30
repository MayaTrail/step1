# Headless live-validation harness for emulation packages.
#
# Drives real deploy -> attack -> destroy for a set of emulations through the
# shipped Celery tasks (invoked synchronously for full tracebacks), then does an
# independent orphan sweep with direct describe/list calls (the Resource Groups
# Tagging API lags minutes and false-positives).
#
# emulations/_dev/ is skipped by the registry (leading underscore), so this file
# never registers as an emulation.
#
# Prereqs:
#   * docker compose up -d db redis backend worker_enterprise
#     (after any backend model change: `docker compose down -v` first — migrations
#      are generated at container start and postgres_data pins a stale schema)
#   * an enterprise user `porttest` with is_verified=True and a real aws_role_arn:
#       docker compose exec -T backend python manage.py shell -c "
#       from apps.users.models import User
#       User.objects.update_or_create(username='porttest', defaults=dict(
#           email='porttest@mayatrail.local', is_verified=True, is_demo=False,
#           aws_role_arn='arn:aws:iam::<ACCT>:role/<ROLE>'))"
#
# Run (worker_enterprise is the only image with the Pulumi CLI):
#   docker compose cp emulations/_dev/live_validate.py worker_enterprise:/app/live_validate.py
#   MSYS_NO_PATHCONV=1 docker compose exec -T -e BATCH=A worker_enterprise python -u /app/live_validate.py
#
# Env vars:
#   BATCH=A|B        pick the built-in list (default A)
#   TESTS=a,b,c      explicit comma-separated emulation_type list (overrides BATCH)
#   TEST_REGION=...  deploy region (default ap-south-1)

import os
import time
import datetime
import traceback

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.dev")
django.setup()

from datetime import timedelta
from django.utils import timezone

from apps.users.models import User
from apps.infrastructure.models import Stack
from apps.emulations.models import EmulationRun
from apps.emulations.registry import get_emulation
from apps.emulations.readiness import resolve_readiness, requires_http_probe
from apps.emulations.tasks import (
    deploy_emulation_stack,
    run_emulation_attack,
    destroy_emulation_stack,
    _assume_user_role,
)
import boto3

REGION = os.environ.get("TEST_REGION", "ap-south-1")

BATCH_A = [
    "aws_persistence_sqs_open_queue_policy",
    "aws_exfiltration_dynamodb_export_to_s3",
    "aws_initial_access_cognito_identity_pool_unauth_creds",
    "aws_defense_evasion_wafv2_disable_web_acl",
    "aws_exfiltration_sns_external_subscription",
    "aws_execution_codepipeline_inject_stage",
    "aws_defense_evasion_vpc_remove_flow_logs",
    "aws_defense_evasion_dns_delete_logs",
]
BATCH_B = [
    "aws_defense_evasion_rds_modify_public_access",
    "aws_exfiltration_rds_share_snapshot",
    "aws_defense_evasion_elbv2_listener_auth_bypass_rule",
    "ecscape",
]
if os.environ.get("TESTS"):
    BATCH = [x.strip() for x in os.environ["TESTS"].split(",") if x.strip()]
elif os.environ.get("BATCH", "A").upper() == "B":
    BATCH = BATCH_B
else:
    BATCH = BATCH_A

user = User.objects.get(username="porttest")
print(f"# user={user.username} role={user.aws_role_arn} region={REGION}")
print(f"# batch={os.environ.get('BATCH', 'A')} ({len(BATCH)} emulations)\n", flush=True)

_creds = _assume_user_role(user)
_sess = boto3.Session(
    aws_access_key_id=_creds["AWS_ACCESS_KEY_ID"],
    aws_secret_access_key=_creds["AWS_SECRET_ACCESS_KEY"],
    aws_session_token=_creds["AWS_SESSION_TOKEN"],
    region_name=REGION,
)
_acct = _sess.client("sts").get_caller_identity()["Account"]
print(f"# orphan-sweep identity: acct={_acct}\n", flush=True)


def sweep():
    """Direct describe/list calls (the Resource Groups Tagging API lags minutes)."""
    found = set()
    try:
        ec2 = _sess.client("ec2")
        for f in ec2.describe_flow_logs().get("FlowLogs", []):
            found.add("ec2:flow-log/" + f["FlowLogId"])
        for v in ec2.describe_vpcs().get("Vpcs", []):
            if v["IsDefault"]:
                continue
            nm = [t["Value"] for t in v.get("Tags", []) if t["Key"] == "Name"]
            if any(k in (nm[0] if nm else "") for k in ("atomic-", "stratus-red-team", "elbv2-bypass", "ecscape")):
                found.add("ec2:vpc/" + v["VpcId"] + " (" + (nm[0] if nm else "") + ")")
        for q in _sess.client("sqs").list_queues().get("QueueUrls", []):
            if any(k in q for k in ("orders-ingest", "payments-processing", "atomic-sns-ext-sub")):
                found.add("sqs:" + q.rsplit("/", 1)[-1])
        for t in _sess.client("sns").list_topics().get("Topics", []):
            if "atomic-sns-ext-sub" in t["TopicArn"]:
                found.add("sns:" + t["TopicArn"].rsplit(":", 1)[-1])
        for tb in _sess.client("dynamodb").list_tables().get("TableNames", []):
            if tb in ("prod-customers", "internal-api-keys"):
                found.add("dynamodb:" + tb)
        for w in _sess.client("wafv2").list_web_acls(Scope="REGIONAL").get("WebACLs", []):
            if "atomic-wafv2" in w["Name"]:
                found.add("wafv2:" + w["Name"])
        for p in _sess.client("codepipeline").list_pipelines().get("pipelines", []):
            if "codepipeline-inject-stage" in p["name"] or "atomic-" in p["name"]:
                found.add("codepipeline:" + p["name"])
        for r in _sess.client("codecommit").list_repositories().get("repositories", []):
            if r["repositoryName"] in ("prod-build-service",):
                found.add("codecommit:" + r["repositoryName"])
        for db in _sess.client("rds").describe_db_instances().get("DBInstances", []):
            if any(k in db["DBInstanceIdentifier"] for k in ("customer-billing", "stratus-red-team-rds")):
                found.add("rds:" + db["DBInstanceIdentifier"])
        for sn in _sess.client("rds").describe_db_snapshots(SnapshotType="manual").get("DBSnapshots", []):
            if "stratus-red-team" in sn["DBSnapshotIdentifier"]:
                found.add("rds-snapshot:" + sn["DBSnapshotIdentifier"])
        for lb in _sess.client("elbv2").describe_load_balancers().get("LoadBalancers", []):
            if "elbv2-bypass" in lb["LoadBalancerName"]:
                found.add("elbv2:" + lb["LoadBalancerName"])
        for cl in _sess.client("ecs").list_clusters().get("clusterArns", []):
            if "ecscape" in cl:
                found.add("ecs:" + cl.rsplit("/", 1)[-1])
        for sec in _sess.client("secretsmanager").list_secrets(MaxResults=100).get("SecretList", []):
            if any(k in sec["Name"] for k in ("build-service/db-master", "prod/rds/master_credentials")):
                found.add("secret:" + sec["Name"])
        for lg in _sess.client("logs").describe_log_groups(logGroupNamePrefix="/mayatrail/atomic").get("logGroups", []):
            found.add("loggroup:" + lg["logGroupName"])
        for lg in _sess.client("logs").describe_log_groups(logGroupNamePrefix="/stratus-red-team").get("logGroups", []):
            found.add("loggroup:" + lg["logGroupName"])
    except Exception as e:
        found.add(f"<direct-scan-error: {e}>")
    try:
        iam = _sess.client("iam")
        pats = ("atomic-", "stratus-red-team", "codepipeline-inject-stage", "ecscape")
        for pg in iam.get_paginator("list_roles").paginate():
            for r in pg["Roles"]:
                if any(p in r["RoleName"] for p in pats):
                    found.add("iam:role/" + r["RoleName"])
        for pg in iam.get_paginator("list_users").paginate():
            for u in pg["Users"]:
                if any(p in u["UserName"] for p in pats):
                    found.add("iam:user/" + u["UserName"])
    except Exception as e:
        found.add(f"<iam-scan-error: {e}>")
    try:
        ci = _sess.client("cognito-identity")
        for p in ci.list_identity_pools(MaxResults=60).get("IdentityPools", []):
            if "prod-mobile-identities" in p["IdentityPoolName"] or "elbv2-bypass" in p["IdentityPoolName"]:
                found.add("cognito-identity-pool:" + p["IdentityPoolName"])
    except Exception as e:
        found.add(f"<cognito-scan-error: {e}>")
    try:
        rr = _sess.client("route53resolver")
        for c in rr.list_resolver_query_log_configs().get("ResolverQueryLogConfigs", []):
            if "stratus-red-team" in c["Name"]:
                found.add("resolver-query-log-config:" + c["Name"])
    except Exception as e:
        found.add(f"<resolver-scan-error: {e}>")
    return found


def deploy_attack(et, stack, row):
    t0 = time.time()
    try:
        deploy_emulation_stack.apply(args=[str(stack.id)]).get(propagate=True)
        stack.refresh_from_db()
        row["deploy"] = stack.status
        row["deploy_s"] = round(time.time() - t0)
        row["outputs_keys"] = sorted((stack.outputs or {}).keys())
    except Exception as e:
        try:
            stack.refresh_from_db()
        except Stack.DoesNotExist:
            pass
        row["deploy"] = "EXCEPTION"
        row["deploy_s"] = round(time.time() - t0)
        row["deploy_err"] = str(e)[:600] + "\n---last_error---\n" + str(getattr(stack, "last_error", ""))[:2000]
        print("!! DEPLOY FAILED\n" + row["deploy_err"], flush=True)
        return

    if row["deploy"] != Stack.Status.READY_FOR_ATTACK:
        print(f"!! deploy ended in status {row['deploy']} (expected ready_for_attack)", flush=True)
        return

    run = EmulationRun.objects.create(
        stack=stack, emulation_type=et,
        status=EmulationRun.Status.PENDING, triggered_by=user,
    )
    t0 = time.time()
    try:
        run_emulation_attack.apply(args=[str(run.id)]).get(propagate=True)
        run.refresh_from_db()
        row["attack"] = run.status
        row["attack_s"] = round(time.time() - t0)
        row["phases"] = f"{run.phase_current}/{run.phase_total}"
        row["stdout_tail"] = "\n".join((run.stdout or "").splitlines()[-50:])
        row["stderr"] = (run.stderr or "")[-2000:]
        print(f"-- attack status={run.status} phases={row['phases']} --", flush=True)
        print(row["stdout_tail"], flush=True)
        if row["stderr"].strip():
            print("--- stderr ---\n" + row["stderr"], flush=True)
    except Exception as e:
        run.refresh_from_db()
        row["attack"] = "EXCEPTION"
        row["attack_s"] = round(time.time() - t0)
        row["attack_err"] = str(e)[:2000]
        row["stdout_tail"] = "\n".join((run.stdout or "").splitlines()[-50:])
        print("!! ATTACK FAILED\n" + row["attack_err"], flush=True)
        print(row["stdout_tail"], flush=True)


# -- pre-clean any leftover porttest stacks ---------------------------------
for s in list(Stack.objects.filter(owner=user)):
    print(f"# pre-clean: destroying leftover {s.name}", flush=True)
    try:
        destroy_emulation_stack.apply(args=[str(s.id)]).get(propagate=True)
    except Exception as e:
        print(f"#   err: {str(e)[:200]}")
        try:
            s.delete()
        except Exception:
            pass

baseline = sweep()
print(f"\n# baseline tagged/named resources: {len(baseline)}")
for a in sorted(baseline):
    print(f"#   {a}")
print(flush=True)

results = []
for et in BATCH:
    row = {"emulation": et}
    entry = get_emulation(et)
    rdy = resolve_readiness(entry) if entry else None
    row["readiness"] = rdy
    row["probe"] = requires_http_probe(rdy) if rdy else None

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%H%M%S")
    stack = Stack.objects.create(
        name=f"porttest-{et[:34]}-{ts}", owner=user, status=Stack.Status.DEPLOYING,
        emulation_type=et, region=REGION, expires_at=timezone.now() + timedelta(hours=2),
    )
    row["stack"] = str(stack.id)
    print(f"\n{'=' * 78}\n>>> {et}\n{'=' * 78}", flush=True)

    try:
        deploy_attack(et, stack, row)
    except Exception as e:
        row["harness_err"] = f"{type(e).__name__}: {e}\n{traceback.format_exc()[-2000:]}"
        print("!! HARNESS EXCEPTION\n" + row["harness_err"], flush=True)
    finally:
        t0 = time.time()
        try:
            res = destroy_emulation_stack.apply(args=[str(stack.id)]).get(propagate=True)
            row["destroy"] = res.get("status", "?") if isinstance(res, dict) else str(res)
            row["destroy_s"] = round(time.time() - t0)
        except Stack.DoesNotExist:
            row["destroy"] = "already-gone"
        except Exception as e:
            row["destroy"] = "EXCEPTION"
            row["destroy_err"] = str(e)[:2000]
            print("!! DESTROY FAILED\n" + row["destroy_err"], flush=True)
        time.sleep(20)  # SQS/other deletions are eventually consistent (~60s worst case)
        try:
            row["orphans"] = sorted(sweep() - baseline)
        except Exception as e:
            row["orphans"] = [f"<sweep-error: {e}>"]
        if row["orphans"]:
            print(f"!! ORPHANS ({len(row['orphans'])}):", flush=True)
            for a in row["orphans"]:
                print("   " + a, flush=True)
        else:
            print("-- no new orphaned resources --", flush=True)
        results.append(row)

# -- summary ---------------------------------------------------------------
print("\n\n" + "#" * 78 + "\n# RESULTS\n" + "#" * 78)
hdr = f'{"emulation":<52} {"deploy":<16} {"probe":<6} {"attack":<11} {"phases":<7} {"destroy":<12} orph'
print(hdr + "\n" + "-" * len(hdr))
for r in results:
    print(f'{r["emulation"]:<52} {str(r.get("deploy")):<16} {str(r.get("probe")):<6} '
          f'{str(r.get("attack", "-")):<11} {str(r.get("phases", "-")):<7} '
          f'{str(r.get("destroy")):<12} {len(r.get("orphans", []))}')
for r in results:
    if any(k in r for k in ("deploy_err", "attack_err", "destroy_err", "harness_err")) or r.get("orphans"):
        print(f'\n### {r["emulation"]}')
        for k in ("deploy_err", "attack_err", "destroy_err", "harness_err"):
            if k in r:
                print(f'-- {k} --\n{r[k]}')
        if r.get("orphans"):
            print("-- orphans --\n" + "\n".join(str(x) for x in r["orphans"]))
print("\n# DONE", flush=True)
