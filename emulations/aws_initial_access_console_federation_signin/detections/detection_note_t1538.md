# Detection Note: T1538 - S3 Enumeration via FederatedUser Session (Data Plane)

## Technique
T1538 - Cloud Service Dashboard, Step 4: ListObjectsV2 on target S3 bucket using
the federation token boto3 session after console access is established.

## Why No Audit Log Detection Applies
This technique operates on the **S3 data plane** (`s3:ListObjectsV2`). S3 data
plane events are NOT included in CloudTrail Management Events by default. They
require explicit opt-in via **S3 CloudTrail Data Events** on a per-bucket or
account-wide basis. Without data events enabled, this step leaves no CloudTrail
trail at all.

## Detection Alternatives

### 1. CloudTrail S3 Data Events (requires opt-in)
Enable S3 data event logging for sensitive buckets. Once enabled, `ListObjectsV2`
calls will appear in CloudTrail with:
- `eventName`: `ListObjects` or `ListObjectsV2`
- `eventSource`: `s3.amazonaws.com`
- `userIdentity.type`: `FederatedUser`
- `requestParameters.bucketName`: the target bucket

SIGMA filter on `userIdentity.type == FederatedUser` for S3 data events will
catch this activity. Data events generate significant volume -- scope to buckets
tagged as sensitive or containing regulated data.

### 2. S3 Server Access Logs
Enable S3 server access logging on target buckets. Access logs record every
request (including `LIST` operations) with the requester's ARN. A FederatedUser
ARN in server access logs is atypical for S3 buckets in most environments.

Server access logs use a different format from CloudTrail and require a separate
log aggregation pipeline. The `Requester` field in the log line will contain the
FederatedUser ARN.

### 3. AWS GuardDuty
GuardDuty's S3 Protection feature (enabled separately) monitors S3 data plane
activity and can generate findings for anomalous access patterns including:
- `Policy:S3/BucketAnonymousAccessGranted`
- `Discovery:S3/MaliciousIPCaller`
- `Exfiltration:S3/ObjectRead.Unusual` (if ML baseline is trained)

A FederatedUser from an unusual IP accessing a bucket with sensitive data may
trigger `Discovery:S3/MaliciousIPCaller.Custom` if the IP is on a threat list.

### 4. Correlation with Control Plane Events (Recommended)
The highest-fidelity approach is to correlate the FederatedUser ConsoleLogin
event (control plane, always logged) with any subsequent S3 API calls from the
same FederatedUser session ARN. Even without data events, the pattern of:

  GetFederationToken (IAMUser) -> ConsoleLogin (FederatedUser) -> [gap in logs]

is itself detectable and implies data plane activity occurred in the window.

### 5. VPC Flow Logs (Network Plane)
If the emulation runner is within a VPC, outbound HTTPS (port 443) connections
to the S3 endpoint (`s3.amazonaws.com` or regional endpoints) will appear in
VPC Flow Logs. Flow logs do not reveal what S3 operations were performed but
can confirm that S3 API calls occurred from the same source IP seen in the
ConsoleLogin event.

## Recommended Coverage Gap Action
For any S3 bucket that contains sensitive, regulated, or credential-adjacent
data: enable CloudTrail S3 Data Events (read+write) and S3 Server Access Logs.
The incremental cost is low relative to the detection value for this technique.
