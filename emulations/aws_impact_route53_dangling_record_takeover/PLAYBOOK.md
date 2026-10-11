# IR Playbook: ATOMIC-route53-dangling-record-takeover — AWS

## Classification

| Field | Value |
|-------|-------|
| Incident Type | Subdomain Takeover / External Defacement |
| Threat Actor | ATOMIC-route53-dangling-record-takeover |
| Platform | aws |
| Severity | Critical |
| MITRE Tactics | Impact |
| MITRE Techniques | T1491.002 — External Defacement |

---

## 1. Preparation

**What should be in place before this incident occurs:**

- CloudTrail management events enabled in all regions (multi-region trail recommended)
- S3 data event logging enabled on sensitive buckets (required to detect PutObject defacement uploads)
- AWS Config rule `s3-bucket-public-access-prohibited` active with SNS alerting
- Route53 hosted zone change logging enabled (CloudWatch Logs or S3)
- SIEM ingesting CloudTrail; alert rules for `CreateBucket` where bucket name matches a known subdomain or hosted zone CNAME target
- Asset inventory of all Route53 CNAME records and their S3 static-website targets — audited regularly for bucket existence
- SCPs or IAM permission boundaries restricting `s3:CreateBucket` and `s3:PutBucketWebsite` to approved roles
- Runbook for emergency Route53 record deletion and S3 bucket quarantine procedures

---

## 2. Identification

### Detection Triggers (Prioritized)

**HIGH-CONFIDENCE — Events that ALWAYS indicate active or attempted subdomain takeover:**

| Audit Event | EventSource | Description | Confidence |
|-------------|-------------|-------------|------------|
| `CreateBucket` | `s3.amazonaws.com` | Bucket name matches an existing Route53 CNAME target | CRITICAL |
| `PutBucketWebsite` | `s3.amazonaws.com` | Static hosting enabled on newly created bucket | HIGH |
| `TestDNSAnswer` | `route53.amazonaws.com` | Attacker-role principal validates live CNAME resolution | HIGH |
| `ListResourceRecordSets` | `route53.amazonaws.com` | Enumeration of all records in a hosted zone | HIGH (in context) |

**MEDIUM-CONFIDENCE — Events that MAY indicate reconnaissance or preliminary access:**

| Audit Event | EventSource | Description | Confidence |
|-------------|-------------|-------------|------------|
| `ListHostedZones` | `route53.amazonaws.com` | Bulk hosted zone enumeration from unfamiliar principal | MEDIUM |
| `DeleteBucket` | `s3.amazonaws.com` | Attacker cleanup of claimed bucket post-defacement | MEDIUM |
| `PutObject` (data plane) | `s3.amazonaws.com` | Upload of defacement HTML — only visible if S3 data event logging enabled | MEDIUM |

---

### Key Investigation Queries

**Step 1 — Identify the attacker principal and session timeline:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=route53.amazonaws.com \
  --start-time "2024-01-01T00:00:00Z" \
  --end-time "2024-01-02T00:00:00Z" \
  --query 'Events[?contains(EventName, `ListHostedZones`) || contains(EventName, `ListResourceRecordSets`) || contains(EventName, `TestDNSAnswer`)].{Time:EventTime,Name:EventName,User:Username,Source:CloudTrailEvent}' \
  --output table
```

**Step 2 — Find all S3 bucket creation events around the same time window:**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateBucket \
  --start-time "2024-01-01T00:00:00Z" \
  --end-time "2024-01-02T00:00:00Z" \
  --query 'Events[].{Time:EventTime,User:Username,Event:CloudTrailEvent}' \
  --output json
```

**Step 3 — Extract bucket name from CreateBucket CloudTrail event and correlate with Route53 CNAMEs:**

```bash
# List all CNAME records across all hosted zones pointing to S3 static website endpoints
ZONE_ID=$(aws route53 list-hosted-zones --query 'HostedZones[].Id' --output text | tr '\t' '\n')
for ZID in $ZONE_ID; do
  aws route53 list-resource-record-sets \
    --hosted-zone-id "$ZID" \
    --query 'ResourceRecordSets[?Type==`CNAME`].{Name:Name,Value:ResourceRecords[0].Value}' \
    --output table
done
```

**Step 4 — Check if any CNAME targets match S3 static-website endpoints and whether the bucket exists:**

```bash
# For a suspected dangling target, e.g. sub.example.com pointing to sub.example.com.s3-website-us-east-1.amazonaws.com
BUCKET_NAME="sub.example.com"
aws s3api head-bucket --bucket "$BUCKET_NAME" 2>&1
# AccessDenied = bucket exists (potentially claimed by attacker); NoSuchBucket = still dangling
```

**Step 5 — Check bucket ownership and website configuration:**

```bash
BUCKET_NAME="<suspected-claimed-bucket>"

# Who owns it? (requires s3:GetBucketAcl or s3:GetBucketOwnershipControls)
aws s3api get-bucket-ownership-controls --bucket "$BUCKET_NAME"

# Is website hosting enabled?
aws s3api get-bucket-website --bucket "$BUCKET_NAME"

# Public access block status
aws s3api get-public-access-block --bucket "$BUCKET_NAME"

# List objects (defacement content)
aws s3 ls "s3://$BUCKET_NAME/"
```

**Step 6 — Confirm live takeover via Route53 test resolution:**

```bash
ZONE_ID="<hosted-zone-id>"
RECORD_NAME="sub.example.com"
aws route53 test-dns-answer \
  --hosted-zone-id "$ZONE_ID" \
  --record-name "$RECORD_NAME" \
  --record-type CNAME
```

**Step 7 — Pull full session activity for attacker principal from CloudTrail:**

```bash
ATTACKER_ARN="arn:aws:iam::<account-id>:role/<attacker-role>"
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$ATTACKER_ARN" \
  --start-time "2024-01-01T00:00:00Z" \
  --end-time "2024-01-02T00:00:00Z" \
  --query 'Events[].{Time:EventTime,Event:EventName,Source:EventSource}' \
  --output table
```

**Step 8 — (If Athena/CloudTrail Lake available) Full cross-service correlation:**

```sql
SELECT
  eventTime, eventName, eventSource, userIdentity.arn, sourceIPAddress, awsRegion,
  requestParameters
FROM cloudtrail_logs
WHERE eventTime BETWEEN '2024-01-01' AND '2024-01-02'
  AND (
    eventSource IN ('route53.amazonaws.com', 's3.amazonaws.com')
    AND eventName IN (
      'ListHostedZones','ListResourceRecordSets','TestDNSAnswer',
      'CreateBucket','PutBucketWebsite','DeleteBucket'
    )
  )
ORDER BY eventTime;
```

---

## 3. Containment

### Immediate Actions (First 15 Minutes)

**Action 1 — Revoke attacker role credentials immediately:**

```bash
ATTACKER_ROLE="<attacker-role-name>"

# List active access keys for the role's associated user (if static key)
aws iam list-access-keys --user-name "<attacker-iam-user>"

# Deactivate the compromised access key
aws iam update-access-key \
  --user-name "<attacker-iam-user>" \
  --access-key-id "<AKIAXXXXXXXXXXXXXXXX>" \
  --status Inactive
```

**Action 2 — Attach an explicit deny policy to the attacker role/user to block all future actions:**

```bash
# Create a deny-all inline policy
aws iam put-user-policy \
  --user-name "<attacker-iam-user>" \
  --policy-name "INCIDENT-RESPONSE-DENY-ALL" \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*"
    }]
  }'
```

**Action 3 — Remove or correct the dangling CNAME record to eliminate the takeover vector:**

```bash
ZONE_ID="<hosted-zone-id>"
RECORD_NAME="sub.example.com."
CURRENT_CNAME_VALUE="sub.example.com.s3-website-us-east-1.amazonaws.com"

# Option A: Delete the dangling CNAME entirely
aws route53 change-resource-record-sets \
  --hosted-zone-id "$ZONE_ID" \
  --change-batch '{
    "Changes": [{
      "Action": "DELETE",
      "ResourceRecordSet": {
        "Name": "'"$RECORD_NAME"'",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{"Value": "'"$CURRENT_CNAME_VALUE"'"}]
      }
    }]
  }'

# Option B: If the record must persist, redirect to a holding page under your control
# Update CNAME to point to an internal/placeholder endpoint you own
```

**Action 4 — Block public access on the attacker-claimed bucket:**

```bash
BUCKET_NAME="<attacker-claimed-bucket>"

aws s3api put-public-access-block \
  --bucket "$BUCKET_NAME" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

**Action 5 — Remove static website hosting configuration from attacker bucket:**

```bash
aws s3api delete-bucket-website --bucket "$BUCKET_NAME"
```

---

## 4. Eradication

### Remove Attacker Access and Artifacts

**Step 1 — Delete the defacement object(s) and empty the attacker bucket:**

```bash
BUCKET_NAME="<attacker-claimed-bucket>"

# Remove all objects (including versioned objects if versioning is on)
aws s3 rm "s3://$BUCKET_NAME/" --recursive

# If versioning is enabled, also remove all versions and delete markers
aws s3api list-object-versions --bucket "$BUCKET_NAME" \
  --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}' \
  --output json | \
  aws s3api delete-objects --bucket "$BUCKET_NAME" --delete file:///dev/stdin
```

**Step 2 — Delete the attacker-created S3 bucket:**

```bash
aws s3api delete-bucket --bucket "$BUCKET_NAME" --region "<bucket-region>"
```

**Step 3 — Delete or rotate the compromised IAM credentials:**

```bash
ATTACKER_USER="<attacker-iam-user>"
KEY_ID="<AKIAXXXXXXXXXXXXXXXX>"

# Delete the key permanently
aws iam delete-access-key \
  --user-name "$ATTACKER_USER" \
  --access-key-id "$KEY_ID"

# Remove the deny-all inline policy once the key is gone
aws iam delete-user-policy \
  --user-name "$ATTACKER_USER" \
  --policy-name "INCIDENT-RESPONSE-DENY-ALL"
```

**Step 4 — Audit all Route53 CNAME records for additional dangling targets:**

```bash
# Enumerate all hosted zones
aws route53 list-hosted-zones --query 'HostedZones[].{ID:Id,Name:Name}' --output table

# For each zone, list CNAMEs pointing to S3 static-website endpoints
aws route53 list-resource-record-sets \
  --hosted-zone-id "<zone-id>" \
  --query 'ResourceRecordSets[?Type==`CNAME` && contains(ResourceRecords[0].Value, `s3-website`)].{Name:Name,Target:ResourceRecords[0].Value}' \
  --output table
```

**Step 5 — Verify each S3 target bucket exists and is owned by your account:**

```bash
# For each CNAME target extracted above, extract the bucket name and verify ownership
SUSPECTED_BUCKET="<bucket-name-from-cname>"
aws s3api get-bucket-location --bucket "$SUSPECTED_BUCKET" 2>&1
# If this returns an error, the bucket is unclaimed — create and lock it immediately or delete the CNAME
```

**Step 6 — Check for any additional bucket policies or public ACLs the attacker may have set:**

```bash
aws s3api get-bucket-policy --bucket "$BUCKET_NAME" 2>/dev/null
aws s3api get-bucket-acl --bucket "$BUCKET_NAME"
```

---

## 5. Recovery

### Restore Clean State

**Step 1 — Re-enable S3 Block Public Access account-level settings if they were overridden:**

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

aws s3control put-public-access-block \
  --account-id "$ACCOUNT_ID" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

**Step 2 — If the CNAME was deleted and the subdomain should still exist, recreate it pointing to a legitimate endpoint:**

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id "<zone-id>" \
  --change-batch '{
    "Changes": [{
      "Action": "CREATE",
      "ResourceRecordSet": {
        "Name": "sub.example.com.",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{"Value": "<legitimate-target-endpoint>"}]
      }
    }]
  }'
```

**Step 3 — Verify no public-facing content is served from attacker infrastructure:**

```bash
# DNS resolution check — confirm CNAME no longer resolves to attacker bucket
aws route53 test-dns-answer \
  --hosted-zone-id "<zone-id>" \
  --record-name "sub.example.com" \
  --record-type CNAME

# HTTP verification from outside
curl -I "http://sub.example.com"
```

**Step 4 — Verify AWS Config rule compliance is restored:**

```bash
aws configservice describe-compliance-by-config-rule \
  --config-rule-names s3-bucket-public-access-prohibited \
  --query 'ComplianceByConfigRules[].{Rule:ConfigRuleName,Status:Compliance.ComplianceType}' \
  --output table
```

**Step 5 — Re-issue new credentials to the affected role/user through a controlled process if it is a legitimate service account:**

```bash
# Create fresh credentials (only after full eradication confirmed)
aws iam create-access-key --user-name "<legitimate-service-account>"
```

**Step 6 — Verify CloudTrail is active and capturing events in all regions:**

```bash
aws cloudtrail describe-trails --include-shadow-trails \
  --query 'trailList[].{Name:Name,MultiRegion:IsMultiRegionTrail,Logging:HasCustomEventSelectors,HomeRegion:HomeRegion}' \
  --output table

aws cloudtrail get-trail-status --name "<trail-name>" \
  --query '{Logging:IsLogging,LastDelivery:LatestDeliveryTime}' \
  --output table
```

---

## 6. Lessons Learned

### Root Cause

A Route53 CNAME record pointed to an S3 static-website endpoint for a bucket that no longer existed (or was never created under the account's control). An attacker with `s3:CreateBucket` and `s3:PutBucketWebsite` permissions — either via a compromised credential or a misconfigured IAM role — was able to claim the unclaimed bucket name and serve arbitrary content through the legitimate subdomain.

### What Would Have Prevented This

| Guardrail | Implementation |
|-----------|---------------|
| Regular DNS hygiene audits | Script that cross-checks all Route53 CNAME targets against owned S3 buckets; alert on any CNAME pointing to an unowned or non-existent bucket. Run nightly. |
| SCP blocking `s3:CreateBucket` outside approved roles | AWS Organizations SCP: `Deny` `s3:CreateBucket` unless principal matches `arn:aws:iam::*:role/ApprovedInfraRole`. |
| S3 account-level Block Public Access | AWS default since April 2023; verify it is not overridden at the account or bucket level. |
| Route53 CNAME to ALIAS migration | Use Route53 Alias records (which can only target AWS resources owned by the same account) instead of CNAME for S3 origins where possible; eliminates the unclaimed-endpoint class of takeover. |
| Bucket existence monitoring via AWS Config | Custom Config rule: any Route53 CNAME pointing to `*.s3-website-*.amazonaws.com` must have a corresponding bucket in the account. Trigger Lambda for auto-remediation. |
| Least-privilege IAM for attacker role | Route53 enumeration (`ListHostedZones`, `ListResourceRecordSets`) should be restricted to read roles with no `s3:CreateBucket` or `s3:PutBucketWebsite` permissions. |
| CloudTrail alerting on `CreateBucket` + CNAME correlation | EventBridge rule: `CreateBucket` events → Lambda checks if bucket name matches any live Route53 CNAME → SNS alert if match found. |

### Key CloudTrail Event Signatures to Permanently Alert On

```
EventName = CreateBucket
  WHERE requestParameters.bucketName MATCHES any Route53 CNAME target value

EventName = PutBucketWebsite
  WHERE userIdentity.arn NOT IN approved_infra_roles

EventName = TestDNSAnswer
  WHERE userIdentity.arn NOT IN approved_dns_ops_roles
```