# Detection Note: T1041 - Exfiltration Over C2 Channel

**Execution plane:** data_plane (classification)
**Audit visible:** Partially - this technique is data-plane by classification, but two of
its constituent actions DO generate CloudTrail management events: GetSecretValue on
hazybeacon-secrets and (if CloudTrail S3 data events are enabled) GetObject on the
terraform.tfstate bait file. The exfil payload transmission over the Lambda URL is not
audit-visible. This is the only technique in the chain where a data-plane classification
technique produces partial CloudTrail evidence.

## Why no SIGMA/KQL rule (for the exfil channel itself)

The actual exfiltration - reading data and transmitting it via HTTPS POST to the Lambda
Function URL - is data-plane traffic. CloudTrail has no visibility into what a Lambda
invocation carries as its payload. However, the *data access* steps that precede the
transmission ARE partially audit-visible (see below).

## Partial CloudTrail coverage (management events)

### GetSecretValue - SecretsManager (CloudTrail management event)
GetSecretValue on hazybeacon-secrets IS a CloudTrail management event. A SIGMA rule was
not generated because this step was classified as data_plane in the TI extract, but
defenders should alert on it:

**Recommended alert condition:**
- eventSource: secretsmanager.amazonaws.com
- eventName: GetSecretValue
- userIdentity.type: IAMUser
- Filter: exclude known application service roles

**KQL sketch (AWSCloudTrail):**
```
AWSCloudTrail
| where EventSource == "secretsmanager.amazonaws.com"
| where EventName == "GetSecretValue"
| where UserIdentityType == "IAMUser"
| project TimeGenerated, EventName, UserIdentityArn, SourceIpAddress, RequestParameters
```

### S3 GetObject on terraform.tfstate (requires CloudTrail S3 data events)
S3 object-level access (GetObject) only appears in CloudTrail if S3 data events are
enabled for hazybeacon-exfil-bucket. By default S3 data events are OFF and this access
is invisible to CloudTrail. Enable via:
  aws cloudtrail put-event-selectors --trail-name hazybeacon-cloudtrail \
    --event-selectors '[{"ReadWriteType":"ReadOnly","DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::hazybeacon-exfil-bucket/"]}]}]'

## Detection alternatives for the exfil channel

### S3 server access logs
S3 server access logging (separate from CloudTrail) records every GetObject with source IP
and requester identity. If enabled on hazybeacon-exfil-bucket, look for GetObject on
terraform.tfstate from hazybeacon-victim-iam-user ARN outside normal application IPs.

### GuardDuty findings
- Exfiltration:S3/MaliciousIPCaller: fires if the source IP of a GetObject matches a
  GuardDuty threat-intel feed entry. Requires the attacker IP to be in the feed.
- UnauthorizedAccess:IAMUser/MaliciousIPCaller: fires on any API call (including
  GetSecretValue) from a known-malicious IP.

### VPC Flow Logs - data transfer volume
For the Lambda Function URL exfil path: in a real exfil, the POST body carries the
exfiltrated payload. VPC flow logs cannot capture payload content but can show anomalous
outbound byte counts from the Lambda ENI. A large POST to *.lambda-url.*.on.aws from
an internal workstation that had not previously communicated with this endpoint is
detectable via flow log volume analysis.

### Post-compromise anti-forensics indicator
- CloudTrail: DeleteFunction on 'UpdateWorker' (eventName: DeleteFunction20150331)
  appears immediately after exfil in the attack chain. This is an audit-visible event.
  Alert on Lambda function deletion by IAM user credentials shortly after Lambda creation
  by the same credential - the creation/deletion pair within a short window is a strong
  indicator of transient attacker infrastructure.

## IOCs from emulation
- GetSecretValue on hazybeacon-secrets from hazybeacon-victim-iam-user (CloudTrail event)
- S3 GetObject on terraform.tfstate bait file (CloudTrail data event if enabled)
- Simulated exfil payload volume logged in emulation output (no real transmission)
- Lambda function 'UpdateWorker' deleted after use - anti-forensics indicator in CloudTrail
