/* ══════════════════════════════════════════
   MayaTrail — GCP IR Playbooks Data
   ══════════════════════════════════════════ */

window.MayaTrail.platforms.gcp = window.MayaTrail.platforms.gcp || {};

window.MayaTrail.platforms.gcp.playbooks = [
  // [0] APT41 GCP Playbook
  {
    steps: [
      {
        title: 'Triage & Initial Detection',
        body: 'Review Cloud Audit Logs for anomalous service account activity. Check for unexpected iam.serviceAccountKeys.create, setIamPolicy, or compute.instances.create events. Correlate with VPC Flow Logs for unusual egress traffic.',
        code: 'gcloud logging read \\\n  "protoPayload.methodName=\\"google.iam.admin.v1.CreateServiceAccountKey\\"" \\\n  --project=my-project \\\n  --freshness=7d \\\n  --format=json'
      },
      {
        title: 'Contain Compromised Service Accounts',
        body: 'Disable all keys for compromised service accounts. Remove IAM bindings granting elevated permissions. If a Workspace admin account is compromised, suspend the user immediately from the Google Admin console.',
        code: 'gcloud iam service-accounts keys list \\\n  --iam-account=compromised-sa@project.iam.gserviceaccount.com\ngcloud iam service-accounts keys delete KEY_ID \\\n  --iam-account=compromised-sa@project.iam.gserviceaccount.com'
      },
      {
        title: 'Assess Cloud Functions & App Engine',
        body: 'APT41 deploys malicious Cloud Functions for persistence. List all recently created/modified functions. Check for functions with unexpected source code, environment variables containing credentials, or connections to external endpoints.',
        code: 'gcloud functions list --format="table(name,status,updateTime,runtime)"\ngcloud functions describe FUNCTION_NAME --format=json'
      },
      {
        title: 'Audit GCS Data Access',
        body: 'Review GCS access logs for bulk downloads or cross-project transfers. Check for objects copied to external buckets. Verify bucket IAM policies for unauthorized allUsers or allAuthenticatedUsers access.',
        code: 'gcloud logging read \\\n  "resource.type=\\"gcs_bucket\\" AND protoPayload.methodName=\\"storage.objects.get\\"" \\\n  --project=my-project --freshness=3d --limit=200'
      },
      {
        title: 'Restore Cloud Logging Integrity',
        body: 'Verify Cloud Audit Logs are enabled for all services. Check that log sinks are routing to the correct BigQuery datasets or GCS buckets. Ensure log retention policies have not been tampered with.',
        code: 'gcloud logging sinks list --project=my-project\ngcloud projects get-iam-policy my-project \\\n  --flatten="bindings[].members" \\\n  --filter="bindings.role:roles/logging.admin"'
      },
      {
        title: 'Post-Incident Hardening',
        body: 'Enable Organization Policy constraints to restrict service account key creation. Enforce VPC Service Controls on sensitive projects. Enable Security Command Center Premium for real-time threat detection. Schedule re-emulation to validate controls.',
        code: 'gcloud resource-manager org-policies enable-enforce \\\n  constraints/iam.disableServiceAccountKeyCreation \\\n  --project=my-project'
      }
    ]
  },
  // [1] Scattered Spider GCP Playbook
  {
    steps: [
      {
        title: 'Detect Social Engineering Activity',
        body: 'Review Google Workspace Admin audit logs for password resets initiated by help desk agents. Check for MFA enrollment changes, recovery email modifications, and suspicious login events from new devices or locations.',
        code: 'gcloud logging read \\\n  "protoPayload.serviceName=\\"login.googleapis.com\\"" \\\n  --project=my-project --freshness=7d --limit=100'
      },
      {
        title: 'Revoke Compromised Sessions',
        body: 'Force sign-out of compromised Workspace accounts. Revoke all OAuth tokens and app-specific passwords. Reset the user password and require MFA re-enrollment with a hardware security key.',
        code: 'gcloud identity groups memberships search-transitive-memberships \\\n  --group-email=admin-group@company.com'
      },
      {
        title: 'Audit IAM Role Bindings',
        body: 'Check for unauthorized role bindings at project and organization level. Scattered Spider escalates through IAM by binding Owner or Editor roles. Review all bindings created in the compromise window.',
        code: 'gcloud projects get-iam-policy my-project \\\n  --flatten="bindings[].members" \\\n  --format="table(bindings.role, bindings.members)" \\\n  --filter="bindings.role:roles/owner OR bindings.role:roles/editor"'
      },
      {
        title: 'Check for Data Exfiltration',
        body: 'Review VPC Flow Logs for large outbound data transfers. Check Cloud DLP findings for sensitive data exposure. Audit GCS access patterns for bulk download activity from compromised accounts.'
      },
      {
        title: 'Implement Identity Hardening',
        body: 'Enforce hardware security keys for all admin accounts. Implement Context-Aware Access policies. Enable Advanced Protection Program for high-value accounts. Restrict Workspace admin API access.',
        code: 'gcloud access-context-manager perimeters list\ngcloud access-context-manager levels list'
      },
      {
        title: 'Deploy Enhanced Monitoring',
        body: 'Enable Security Command Center Event Threat Detection. Configure alerting for privileged role grants, service account key creation, and Workspace admin actions. Set up log-based alerts in Cloud Monitoring.'
      }
    ]
  },
  // [2] APT29 GCP Playbook
  {
    steps: [
      {
        title: 'Detect Token Theft Indicators',
        body: 'Review Cloud Audit Logs for service account token generation events. Check for GenerateAccessToken or SignJwt calls from unexpected principals. Monitor for metadata endpoint access from compromised GCE instances.',
        code: 'gcloud logging read \\\n  "protoPayload.methodName=\\"GenerateAccessToken\\" OR\n   protoPayload.methodName=\\"SignJwt\\"" \\\n  --project=my-project --freshness=7d'
      },
      {
        title: 'Contain Cross-Cloud Lateral Movement',
        body: 'APT29 pivots across cloud providers. Check for Workload Identity Federation configurations that might allow AWS or Azure identities to access GCP. Review and restrict external identity providers.',
        code: 'gcloud iam workload-identity-pools list --location=global\ngcloud iam workload-identity-pools providers list \\\n  --workload-identity-pool=POOL_ID --location=global'
      },
      {
        title: 'Audit GCE Metadata Access',
        body: 'Review network logs for connections to the GCE metadata endpoint (169.254.169.254). Identify SSRF vulnerabilities in applications running on GCE. Enforce metadata concealment where possible.',
        code: 'gcloud compute instances describe INSTANCE_NAME \\\n  --format="value(metadata.items)"\ngcloud compute project-info describe \\\n  --format="value(commonInstanceMetadata.items)"'
      },
      {
        title: 'Verify Audit Log Integrity',
        body: 'Confirm all Data Access Audit Logs are enabled. Check for deleted or modified log sinks. Ensure logs are exported to a separate security project with restricted access. Verify Cloud Logging retention settings.',
        code: 'gcloud logging sinks list --project=my-project\ngcloud logging sinks describe _Default --project=my-project'
      },
      {
        title: 'Deploy Detection Rules',
        body: 'Import Chronicle YARA-L rules for APT29 TTPs into your Security Operations Center. Enable Security Command Center threat detection. Create custom Cloud Monitoring alerts for high-risk IAM operations.'
      },
      {
        title: 'Harden GCP Environment',
        body: 'Enable VPC Service Controls to prevent data exfiltration. Enforce Organization Policies restricting external sharing, public IP assignment, and service account key creation. Implement defense-in-depth with Binary Authorization for GKE.'
      }
    ]
  },
  // [3] TeamTNT GCP Playbook
  {
    steps: [
      {
        title: 'Detect Cryptomining Activity',
        body: 'Check Cloud Monitoring for unexpected CPU/GPU utilization spikes on GCE instances and GKE nodes. Review billing alerts for unusual compute costs. Search for known mining pool domains in VPC Flow Logs.',
        code: 'gcloud compute instances list \\\n  --format="table(name,zone,status,machineType)" \\\n  --filter="status:RUNNING"\ngcloud monitoring dashboards list'
      },
      {
        title: 'Isolate Compromised GKE Workloads',
        body: 'Apply NetworkPolicies to block egress from suspicious pods. Cordon and drain compromised nodes. Review pod specifications for privileged containers, hostPID, and hostNetwork settings.',
        code: 'kubectl get pods --all-namespaces \\\n  -o jsonpath=\'{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" privileged:"}{.spec.containers[*].securityContext.privileged}{"\\n"}{end}\'\nkubectl cordon NODE_NAME'
      },
      {
        title: 'Audit Metadata Credential Access',
        body: 'TeamTNT steals GCP credentials from the metadata endpoint. Review which service accounts were assigned to compromised instances. Rotate all affected service account keys immediately.',
        code: 'gcloud compute instances describe INSTANCE_NAME \\\n  --format="value(serviceAccounts[].email)"\ngcloud iam service-accounts keys list \\\n  --iam-account=SA_EMAIL --managed-by=user'
      },
      {
        title: 'Remove Malicious Containers & Workloads',
        body: 'Delete malicious pods, deployments, and cron jobs created by the attacker. Check for DaemonSets that deploy miners across all nodes. Review container images for known cryptominer signatures.',
        code: 'kubectl get cronjobs --all-namespaces\nkubectl delete deployment MINER_DEPLOYMENT -n NAMESPACE'
      },
      {
        title: 'Harden GKE Against Container Threats',
        body: 'Enable GKE Workload Identity to eliminate node-level service account keys. Enforce Pod Security Standards. Enable Binary Authorization to restrict container images. Implement network policies for least-privilege pod communication.',
        code: 'gcloud container clusters update CLUSTER \\\n  --workload-pool=PROJECT.svc.id.goog \\\n  --zone=us-central1-a'
      }
    ]
  },
  // [4] LAPSUS$ GCP Playbook
  {
    steps: [
      {
        title: 'Detect Okta/Workspace Compromise',
        body: 'Review Google Workspace Admin logs for unusual admin actions. Check Okta system logs for unauthorized app assignments or policy changes. Identify accounts that were compromised through credential purchase or SIM swapping.',
        code: 'gcloud logging read \\\n  "protoPayload.serviceName=\\"admin.googleapis.com\\"" \\\n  --project=my-project --freshness=7d --format=json'
      },
      {
        title: 'Contain Compromised Admin Accounts',
        body: 'Immediately suspend compromised Workspace admin accounts. Revoke all active sessions and tokens. Remove delegated admin privileges. Enable super admin recovery options with hardware security keys only.',
        code: 'gcloud identity groups memberships list \\\n  --group-email=gcp-organization-admins@company.com'
      },
      {
        title: 'Audit Source Code Repository Access',
        body: 'LAPSUS$ targets source code. Check Cloud Source Repositories access logs. Review GitHub/GitLab integrations for unauthorized access. Verify no source code was cloned or exported during the compromise window.',
        code: 'gcloud source repos list\ngcloud logging read \\\n  "resource.type=\\"cloud_source_repository\\"" \\\n  --project=my-project --freshness=7d'
      },
      {
        title: 'Check for Public Data Exposure',
        body: 'LAPSUS$ leaks stolen data on Telegram. Check if any GCS buckets were made public. Review IAM policies for allUsers bindings. Verify no project data was shared with external Google accounts.'
      },
      {
        title: 'Rotate All Credentials & Secrets',
        body: 'Rotate all service account keys, API keys, and secrets stored in Secret Manager. Update all CI/CD pipeline credentials. Regenerate OAuth client secrets for all applications.',
        code: 'gcloud secrets list --project=my-project\ngcloud secrets versions list SECRET_NAME --project=my-project'
      },
      {
        title: 'Implement Anti-LAPSUS$ Controls',
        body: 'Enforce FIDO2 security keys for all admin accounts. Implement phishing-resistant MFA across the organization. Restrict Workspace admin roles. Enable Advanced Protection Program for executives and admins.'
      }
    ]
  }
];
