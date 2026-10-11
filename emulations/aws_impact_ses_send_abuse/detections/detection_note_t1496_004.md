# Detection Note: S3 Object Access During Campaign Staging (T1496.004 - Data Plane)

## Why No SIGMA/KQL Rule

Step 4 of this emulation accesses the campaigns S3 bucket to retrieve HTML email
templates and the recipient CSV. The object-level calls — `ListObjectsV2` and
`GetObject` — are S3 **data-plane** operations. CloudTrail does not emit management
events for these by default; only `ListBuckets` is a management-plane event and IS
covered by `sigma_T1496.004_s3_campaign_discovery.yml`.

---

## Detection Alternatives

### 1. S3 Server-Access Logging (per-bucket)

Enable server-access logging on the campaigns bucket. Every `GetObject`,
`ListObjectsV2`, `PutObject`, and `DeleteObject` is logged to a destination bucket.
Log format includes: `Requester`, `Key`, `Operation`, `HTTP status`, `Error code`,
`Bytes sent`, and `Timestamp`.

Alert condition:
- `Operation: REST.GET.OBJECT` on keys matching `*.html` or `*.csv` from an
  IAM principal (AssumedRole) that has not previously accessed the bucket.
- `Operation: REST.GET.BUCKET` (ListObjectsV2) from same principal.

### 2. CloudTrail S3 Data Events (explicit opt-in, additional cost)

CloudTrail can be configured to log S3 data events for specific buckets or
all buckets. When enabled:

```yaml
# SIGMA (once data events are on)
logsource:
    product: aws
    service: cloudtrail
detection:
    s3_data_read:
        eventSource: 's3.amazonaws.com'
        eventName:
            - 'GetObject'
            - 'ListObjectsV2'
        requestParameters.bucketName|contains: 'campaigns'
        userIdentity.type: 'AssumedRole'
```

KQL equivalent:
```kql
AWSCloudTrail
| where EventSource == "s3.amazonaws.com"
| where EventName in ("GetObject", "ListObjectsV2")
| where RequestParameters contains "campaigns"
| where UserIdentityType == "AssumedRole"
```

### 3. GuardDuty S3 Protection

GuardDuty S3 Protection monitors object-level API calls with ML-based anomaly
detection. Relevant findings that may fire during emulation:

- `Discovery:S3BucketEnumeration` — unusual ListObjectsV2 from an IAM role
- `Exfiltration:S3ObjectRead` — GetObject of sensitive keys (CSV, credentials)
  from a role that has not previously accessed that bucket

S3 Protection must be enabled per account/region in the GuardDuty console.

### 4. Macie (sensitive data in templates or recipient list)

If the campaigns bucket contains a recipient CSV with PII (names, emails), Amazon
Macie will flag it as containing personal data. Macie findings do not fire in
real-time on access events, but a Macie sensitive-data finding on the bucket
combined with a CloudTrail ListBuckets event from an unusual role is a correlated
indicator worth surfacing in a SIEM rule.

### 5. VPC Flow Logs

If the attacker role is operating from within a VPC (Lambda or ECS in the lab),
VPC Flow Logs capture the S3 VPC endpoint traffic. An unusual source ENI making
many `443/tcp` requests to the S3 VPC endpoint in a short window (many small
GetObject calls) is visible here even without S3 data event logging.

---

## Emulation-Specific Notes

- The bucket `atomic-ses-send-abuse-campaigns-bucket` is seeded with HTML templates
  and a recipient CSV during infrastructure deployment.
- The attacker role's IAM policy permits `s3:GetObject` and `s3:ListBucket` only on
  this specific bucket and only to the mailbox simulator recipient address.
- Object access in step 4 is the staging phase; the actual send in step 7 uses the
  in-memory template and recipient list, not a re-read from S3.

---

# Detection Note: SES SendEmail (T1496.004 - Data Plane)

## Why No SIGMA/KQL Rule

`SendEmail` is an SES **data-plane** call. AWS does not emit CloudTrail management
events for SES sending operations. No management-plane log record is created when
`ses:SendEmail` or `ses:SendRawEmail` is called, regardless of whether it succeeds
or returns `MessageRejected`.

In this emulation, step 7 sends to the AWS mailbox simulator and is expected to
return `MessageRejected` because the sender identity (`noreply@lab.example.com`) is
unverified. That error is also invisible in CloudTrail.

---

## Detection Alternatives

### 1. SES CloudWatch Event Destinations (highest fidelity, near real-time)

Configure an SES **configuration set** with a CloudWatch event destination. SES
publishes send, bounce, complaint, and reject events as CloudWatch metrics and
(optionally) as EventBridge events. Key metrics to alert on:

| Metric | Namespace | Threshold |
|---|---|---|
| `Send` | `AWS/SES` | Spike above rolling baseline |
| `Bounce` | `AWS/SES` | > 5% bounce rate |
| `Complaint` | `AWS/SES` | > 0.1% complaint rate |
| `Reject` | `AWS/SES` | Any `MessageRejected` events |

CloudWatch Alarms on `Reject` and `Complaint` fire within minutes of abuse. In
the emulation, the configuration set (`atomic-ses-send-abuse-config-set`) routes
these events to CloudWatch — the Reject metric will increment when step 7 runs.

### 2. SES Feedback Notifications (SNS)

Enable SES feedback notifications to an SNS topic for bounce and complaint events.
A sudden spike in complaints from a new sender identity is a strong abuse indicator.
Wire the SNS topic to a Lambda or EventBridge rule for automated triage.

### 3. SES Account-Level Sending Metrics (CloudWatch)

Monitor the `AWS/SES` namespace metric `Send` with a PeriodOverPeriod anomaly
detector. A sudden volume spike — especially from a newly registered identity —
indicates abuse even without per-message visibility.

### 4. GuardDuty (if enabled with S3/CloudTrail data events)

GuardDuty does not have a native finding for SES send abuse. However, the
surrounding recon events (GetSecretValue on SES credentials, ListBuckets) can
trigger:
- `CredentialAccess:SecretsManagerSecret` — on the GetSecretValue call in step 5
- `Discovery:S3BucketEnumeration` — on the ListBuckets call in step 4 (if the role
  is flagged as unusual)

### 5. SES CloudTrail Data Events (if enabled)

AWS CloudTrail can be configured to log SES **data events** (additional cost).
When enabled, `SendEmail` and `SendRawEmail` appear in CloudTrail with full
request parameters including `Source`, `Destination`, `Subject`, and `Body`.
This enables:
- Exact SIGMA/KQL matching on sender identity and recipient domain
- Correlation with the management-plane events from steps 2-6 in the same session

Detection condition once data events are enabled:
```
eventSource: ses.amazonaws.com
eventName:   SendEmail | SendRawEmail
requestParameters.source: "noreply@*.example.com"   # attacker identity pattern
```

### 6. VPC Flow Logs / Network Proxy (SMTP path)

If the environment routes outbound SMTP through a proxy or NAT gateway, VPC Flow
Logs will capture port-25 or port-587 traffic. A NAT gateway seeing port-587
traffic from an ECS task or Lambda that doesn't normally send mail is suspicious.

---

## Emulation-Specific Notes

- Step 7 sends to `success@simulator.amazonses.com` — the AWS mailbox simulator
  address. No real recipient receives mail. The IAM deny condition on the attacker
  role additionally blocks sending to any non-simulator address.
- The `MessageRejected` error is expected because `noreply@lab.example.com` is
  unverified. `example.com` is IANA-reserved and cannot pass DNS DKIM/SPF checks.
- The configuration set in the infrastructure routes Reject events to CloudWatch,
  so the Reject metric WILL fire during live emulation even though the send fails.
