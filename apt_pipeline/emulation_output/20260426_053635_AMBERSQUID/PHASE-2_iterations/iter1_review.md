```json
{
  "verdict": "APPROVED",
  "summary": "Infrastructure correctly models the AMBERSQUID credential-theft-to-multi-service-cryptomining kill chain with proper sandbox isolation. Attack surface (over-permissioned victim IAM user with long-lived credentials injected into ECS task environment) faithfully replicates the documented TTP. All 10 targeted AWS services are covered in the victim policy. Expensive techniques (T1496, T1610, T1578.002, T1525) are correctly scoped as simulated per operational_notes. Bait resources use realistic production naming and complete the discovery chain. Estimated cost ~$0.006/hr is minimal.",
  "operator_notes": [
    "Victim policy uses Resource:\"*\" on all statements — INTENTIONAL: AMBERSQUID operates across 16 regions and 10+ services; scoping would break emulation fidelity. Assumes dedicated emulation AWS account — do NOT deploy in a shared account.",
    "ambersquid-cloudtrail-bucket requires an explicit aws.s3.BucketPolicy resource granting the CloudTrail service principal s3:PutObject and s3:GetBucketAcl — documented in config notes but not listed as a separate resource. Trail creation will fail without it.",
    "ambersquid-igw config notes describe a route table, default route (0.0.0.0/0 → IGW), and route table association — these must be created as separate Pulumi resources. Not functionally critical since T1610 is simulated (task definition registered only, no tasks run), but required if any container is launched for demonstration.",
    "Attack-created IAM roles (AWSCodeCommit-Role, sugo-role, ecsTaskExecutionRole) are created at runtime by attack.py and NOT managed by Pulumi — they survive pulumi destroy. The emulation script MUST include its own cleanup phase. If it crashes mid-run, manually delete these roles — ecsTaskExecutionRole will have AdministratorAccess attached.",
    "ambersquid-terraform-state-bucket needs an aws.s3.BucketObjectv2 resource to upload the fake terraform.tfstate containing the honey IAM user's access key ID and secret — without this object the bait chain is incomplete and T1580 enumeration yields an empty bucket.",
    "Security group allows only TCP/443 egress — sufficient for all AWS API calls. Mining pool ports (3333, 4444, 5555, 7777, 8888, 9999, 14444, 45560) are implicitly denied. DNS to the Amazon-provided resolver (VPC base+2) is exempt from security group filtering.",
    "sandbox_vpc.isolation_rules says 'NAT for outbound only' but implementation uses a public subnet with IGW and mapPublicIpOnLaunch — functionally equivalent given the SG blocks all ingress. Omitting the NAT Gateway saves ~$0.045/hr.",
    "No permission boundary on victim user — INTENTIONAL: AMBERSQUID creates ecsTaskExecutionRole with AdministratorAccess via iam:AttachRolePolicy. A boundary would prevent this and break emulation fidelity.",
    "iam:CreateUser is in victim policy but AMBERSQUID's documented kill chain only creates roles, not users — minor over-permission, harmless in a dedicated account but worth noting for future policy tightening."
  ]
}
```