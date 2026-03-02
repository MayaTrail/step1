import type { Playbook } from '@/types'

export const awsPlaybooks: Playbook[] = [
  // APT29 Playbook
  {
    steps: [
      {
        title: 'Triage & Initial Detection',
        body: 'Verify alert fidelity. Check CloudTrail for anomalous API calls originating from unusual IP addresses or user agents. Look for GetObject calls at unusual volume or from unexpected principals. Confirm whether the activity is from a known service account or a potentially compromised identity.',
        code: `aws cloudtrail lookup-events \\
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \\
  --start-time 2024-01-01T00:00:00Z \\
  --max-results 50`,
      },
      {
        title: 'Identity Containment',
        body: 'If compromise is confirmed, immediately disable the affected IAM user or role. Revoke all active sessions. Rotate access keys. Review and document all permissions associated with the affected identity before removal to understand potential blast radius.',
        code: `aws iam update-access-key \\
  --access-key-id AKIAIOSFODNN7EXAMPLE \\
  --status Inactive
aws iam delete-login-profile --user-name compromised-user`,
      },
      {
        title: 'Scope Assessment \u2014 What Was Accessed?',
        body: 'Enumerate all resources accessed by the compromised identity in the window of compromise. Query S3 access logs, CloudWatch, and GuardDuty findings. Identify if any data exfiltration occurred via cross-account replication, presigned URLs, or direct transfer.',
      },
      {
        title: 'Re-enable & Validate Logging',
        body: 'APT29 is known to disable CloudTrail logging as part of defense evasion. Verify all CloudTrail trails are active and logging to a tamper-proof S3 bucket with Object Lock enabled. Ensure GuardDuty and Security Hub are active in all regions.',
        code: `aws cloudtrail get-trail-status --name management-trail
aws guardduty list-detectors`,
      },
      {
        title: 'Deploy Detection Rules',
        body: 'Apply the SIGMA and KQL detection rules generated from this emulation run. Import into your SIEM. Enable the associated GuardDuty threat intelligence feeds. Create CloudWatch alarms for the specific CloudTrail event patterns observed.',
      },
      {
        title: 'Post-Incident Review & Hardening',
        body: 'Document findings in your security ticket system. Apply IAM guardrails to prevent re-occurrence: enforce MFA, enforce IMDSv2, restrict PassRole permissions. Schedule a re-run of this emulation after remediation to validate controls are effective.',
      },
    ],
  },
  // APT41 Playbook
  {
    steps: [
      {
        title: 'Initial Alert Validation',
        body: 'Review GuardDuty findings for unusual IAM activity, unauthorized EC2 launches, or suspicious API calls. Cross-reference with CloudTrail for CreateUser, AttachRolePolicy, or RunInstances events from unknown source IPs.',
        code: `aws guardduty list-findings --detector-id <detector-id> \\
  --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}'`,
      },
      {
        title: 'Isolate Compromised Resources',
        body: 'Isolate affected EC2 instances by applying a restrictive security group (deny all inbound/outbound). Disable compromised IAM users and revoke sessions. Preserve evidence by creating EBS snapshots before any remediation.',
        code: `aws ec2 modify-instance-attribute \\
  --instance-id i-0123456789abcdef0 \\
  --groups sg-isolation-only
aws iam put-user-policy --user-name compromised --policy-name DenyAll \\
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'`,
      },
      {
        title: 'Audit CI/CD Pipeline Integrity',
        body: 'APT41 targets supply chains. Review CodePipeline and CodeBuild histories for unauthorized modifications. Check for rogue buildspec files, injected build commands, or unauthorized artifact uploads.',
        code: `aws codepipeline list-pipeline-executions --pipeline-name production-pipeline
aws codebuild batch-get-builds --ids <build-id>`,
      },
      {
        title: 'Hunt for Persistence Mechanisms',
        body: 'Search for rogue IAM users, roles with overly permissive policies, unauthorized Lambda functions, and EC2 instances in unexpected regions. Check for backdoor access keys attached to service accounts.',
      },
      {
        title: 'Remediate & Rotate Credentials',
        body: 'Rotate all potentially exposed access keys and passwords. Remove unauthorized IAM entities. Redeploy affected infrastructure from known-good templates. Update SCPs to restrict high-risk actions.',
        code: `aws iam list-access-keys --user-name <user>
aws iam create-access-key --user-name <user>
aws iam delete-access-key --access-key-id <old-key> --user-name <user>`,
      },
      {
        title: 'Post-Incident Hardening',
        body: 'Enable AWS Organizations SCPs to prevent CreateUser in non-approved accounts. Enable Config Rules to detect policy drift. Schedule re-run of APT41 emulation to validate remediation.',
      },
    ],
  },
  // Lazarus Group Playbook
  {
    steps: [
      {
        title: 'Alert Triage \u2014 Financial Targeting Indicators',
        body: 'Review CloudTrail for unusual KMS key operations (CreateKey, ScheduleKeyDeletion, ReEncrypt). Check for unauthorized Lambda function deployments targeting financial data processing systems.',
        code: `aws cloudtrail lookup-events \\
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateKey \\
  --start-time 2024-01-01T00:00:00Z`,
      },
      {
        title: 'Contain KMS Ransomware Activity',
        body: 'If KMS-based ransomware is detected, immediately disable the attacker-controlled KMS key. Apply a key policy that denies all decrypt operations. Identify all S3 objects re-encrypted with the malicious key.',
        code: `aws kms disable-key --key-id <attacker-key-id>
aws kms put-key-policy --key-id <attacker-key-id> --policy-name default \\
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"kms:*","Resource":"*"}]}'`,
      },
      {
        title: 'Assess Data Encryption Impact',
        body: 'Determine the scope of data encrypted by the attacker. List all S3 objects using the attacker KMS key. Check for RDS snapshots encrypted with unauthorized keys. Verify backup integrity.',
        code: `aws s3api list-objects-v2 --bucket <bucket-name> \\
  --query "Contents[?ServerSideEncryption=='aws:kms']"`,
      },
      {
        title: 'Restore from Clean Backups',
        body: 'Restore affected S3 objects from versioning or cross-region replication. Restore RDS from pre-incident snapshots. Verify data integrity using checksums against known-good baselines.',
      },
      {
        title: 'Deploy Financial-Specific Detections',
        body: 'Create CloudWatch alarms for KMS key creation, ScheduleKeyDeletion, and ReEncrypt operations. Enable GuardDuty S3 protection. Implement real-time alerting for high-value financial data access patterns.',
      },
      {
        title: 'Harden Against Crypto-Targeting',
        body: 'Implement SCP restricting KMS key creation. Enable S3 Object Lock on critical financial data. Require approval workflows for Lambda deployments in production. Review and restrict Lambda execution roles.',
      },
    ],
  },
  // APT33 Playbook
  {
    steps: [
      {
        title: 'Detect Password Spray Activity',
        body: 'Monitor CloudTrail for high volumes of failed ConsoleLogin events from distributed IP addresses. Check for patterns consistent with password spraying: same password across many accounts in rapid succession.',
        code: `aws cloudtrail lookup-events \\
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \\
  --start-time 2024-01-01T00:00:00Z \\
  --max-results 100`,
      },
      {
        title: 'Enforce MFA & Block Compromised Accounts',
        body: 'Immediately enforce MFA on all IAM users and root accounts. Disable any accounts showing successful login from suspicious IPs post-spray. Enforce password rotation for all potentially affected accounts.',
      },
      {
        title: 'Audit Cloud Resource Enumeration',
        body: 'Review CloudTrail for reconnaissance activities: ListBuckets, DescribeInstances, DescribeDBInstances, ListFunctions. Identify the scope of what the attacker discovered about your infrastructure.',
        code: `aws cloudtrail lookup-events \\
  --lookup-attributes AttributeKey=EventName,AttributeValue=DescribeDBInstances`,
      },
      {
        title: 'Check for Data Destruction Indicators',
        body: 'APT33 is associated with wiper attacks. Check for DeleteObject, DeleteBucket, DeleteDBInstance, or TerminateInstances events. Verify S3 versioning and deletion protection are enabled on critical buckets.',
      },
      {
        title: 'Harden Against Destructive Attacks',
        body: 'Enable S3 Object Lock, MFA Delete on critical buckets. Enable RDS deletion protection. Use AWS Backup for automated cross-region backup. Restrict iam:Delete* and s3:DeleteObject permissions via SCPs.',
        code: `aws s3api put-bucket-versioning \\
  --bucket critical-data \\
  --versioning-configuration Status=Enabled,MFADelete=Enabled`,
      },
    ],
  },
  // FIN7 Playbook
  {
    steps: [
      {
        title: 'Detect Initial Compromise Vector',
        body: 'Review email gateway logs for spearphishing indicators. Check CloudTrail for API calls from unusual user agents or geolocations. Investigate any new IAM access keys created in the timeframe of suspected compromise.',
        code: `aws iam list-access-keys --user-name <suspect-user>
aws cloudtrail lookup-events \\
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey`,
      },
      {
        title: 'Isolate EKS Workloads',
        body: 'If EKS compromise is suspected, apply NetworkPolicies to isolate affected pods. Review pod specifications for container escape indicators. Check for privileged containers or hostPath mounts.',
        code: `kubectl get pods --all-namespaces -o json | \\
  jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.name'`,
      },
      {
        title: 'Investigate IMDS Credential Theft',
        body: 'Check if IMDSv1 is enabled on compromised instances. Review VPC Flow Logs for connections to 169.254.169.254. Identify which role credentials were exposed through the metadata service.',
        code: `aws ec2 describe-instances --instance-ids i-0123456789abcdef0 \\
  --query "Reservations[].Instances[].MetadataOptions"`,
      },
      {
        title: 'Contain Ransomware Deployment',
        body: 'If ransomware indicators detected, immediately snapshot all EBS volumes. Isolate affected instances. Check for unauthorized KMS key usage. Preserve CloudTrail and VPC Flow Logs as forensic evidence.',
      },
      {
        title: 'Remediate SSM & Credential Exposure',
        body: 'Rotate all SSM-managed credentials. Enforce IMDSv2 across all EC2 instances. Revoke any compromised session tokens. Update IAM policies to follow least-privilege principles.',
        code: `aws ec2 modify-instance-metadata-options \\
  --instance-id i-0123456789abcdef0 \\
  --http-tokens required \\
  --http-endpoint enabled`,
      },
      {
        title: 'Deploy Financial Sector Hardening',
        body: 'Implement PCI DSS-aligned security controls. Enable GuardDuty EKS protection. Deploy AWS WAF on all public-facing applications. Enable real-time alerting for credential-related API calls.',
      },
    ],
  },
]
