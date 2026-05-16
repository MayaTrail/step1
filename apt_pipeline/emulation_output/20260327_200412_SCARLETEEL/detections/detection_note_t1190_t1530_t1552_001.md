# Detection Gap Note — T1190, T1530, T1552.001

## Why no Sigma/KQL rules exist for these techniques

---

### T1190 — Exploit Public-Facing Application

**Why no CloudTrail rule:** The Flask command injection exploit (`POST /cmd`) happens entirely
at the HTTP/data-plane layer. AWS CloudTrail only captures AWS API calls (control plane) —
it has no visibility into HTTP traffic to EC2 instances.

**What DOES generate signal:**
- **VPC Flow Logs** — show inbound TCP connections to the EC2 instance on port 8080
- **EC2 instance console output / cloud-init logs** — show Docker build and container start
- **Container-level logging** (if configured) — would show the exploit POST request

**Recommended detective controls:**
1. Deploy a **WAF (Web Application Firewall)** in front of port 8080 with managed rule groups for command injection (`AWSManagedRulesCommonRuleSet` + `AWSManagedRulesKnownBadInputsRuleSet`)
2. Enable **VPC Flow Logs** and alert on unexpected inbound connections to compute instances
3. Restrict the security group to known IP ranges instead of `0.0.0.0/0`
4. Run containers in **read-only mode** with no shell access

---

### T1530 — Data from Cloud Storage (S3 GetObject)

**Why no CloudTrail rule:** `s3:GetObject` is a **data event**, not a management event.
CloudTrail does NOT log individual `GetObject` calls unless S3 data event logging is explicitly
enabled on the trail via `PutEventSelectors`. Without this, the attacker can download every
object in every S3 bucket without leaving a single CloudTrail trace.

**What DOES generate signal with proper configuration:**
- **CloudTrail S3 data events** — enable with:
  ```bash
  aws cloudtrail put-event-selectors --trail-name <trail> \
    --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true,
      "DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3"]}]}]'
  ```
- **S3 Access Logs** — per-bucket logging to a separate log bucket

**Detection rule (once data events are enabled):**
Alert on `GetObject` calls where:
- `userIdentity.principalId` contains `:i-` (EC2 instance role)
- `sourceIPAddress` is not an AWS-internal address
- `requestParameters.bucketName` contains the bucket of interest

**SCARLETEEL impact:** The attacker exfiltrated objects from `scarleteel-dummy-logs`,
`scarleteel-dummy-scripts`, and `scarleteel-trail-logs` without any CloudTrail evidence
because data event logging was not enabled. Only `ListObjectsV2` (management event) is visible.

---

### T1552.001 — Credentials in Files (terraform.tfstate in S3)

**Why no CloudTrail rule:** Same reason as T1530 — `s3:GetObject` on `terraform.tfstate` is a
**data event** and invisible without explicit S3 data event logging.

**Indirect detective controls:**
1. **Enable S3 data events** (see T1530 above) to capture the `GetObject` on `terraform.tfstate`
2. **Alert on lateral movement consequence** — after this step, the attacker uses the stolen
   IAM credentials: `sts:GetCallerIdentity` from the bait user is the detectable signal
   (covered by `sigma_t1552_005.yml` for the EC2 role exfiltration, and directly observable
   as a principal change in CloudTrail)
3. **Preventive controls:** Never store IAM access keys in Terraform state files; use
   IAM roles with OIDC federation instead of long-term credentials

**Root cause fix:** Remove `aws_iam_access_key` resources from Terraform state entirely.
Use dynamic credentials (EC2 instance profiles, OIDC, etc.) instead of static keys.
If static keys must be managed by Terraform, use remote state with encryption and restrict
S3 bucket access via IAM resource policies.
