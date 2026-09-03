# Detection Note: T1530 - DynamoDB Export S3 Data Plane Writes

## Technique
MITRE ATT&CK T1530 - Data from Cloud Storage
Sub-activity: DynamoDB service principal writing exported table data to S3 sink bucket

## Why This Is a Data Plane Blind Spot

After `ExportTableToPointInTime` is triggered via the control plane, all actual
data movement is performed by the **DynamoDB service principal**
(`dynamodb.amazonaws.com`), not by the victim-role STS session that issued the
API call. This means:

- **No CloudTrail management events** are generated for the S3 PutObject calls.
- **No CloudTrail data events** appear under the victim-role ARN.
- The only CloudTrail signal is the single `ExportTableToPointInTime` event
  (covered by `sigma_T1530_dynamodb_export_table_to_s3.yml`).

## Detection Alternatives

### 1. S3 Server Access Logs (Recommended - Data Plane)
Enable S3 server access logging on the export sink bucket.
After a successful export the log will show:
- **Requester**: `dynamodb.amazonaws.com` (the DynamoDB service principal)
- **Operation**: `REST.PUT.OBJECT`
- **Key pattern**: `AWSLogs/{account_id}/DynamoDB/{region}/{export_id}/AWSDynamoDB/...`
- **Object count**: One manifest file + one or more data chunk files (`.json.gz` or `.ion.gz`)

Anomaly signal: S3 PutObject calls from `dynamodb.amazonaws.com` to a bucket that
is not a known DynamoDB backup destination, especially to prefixes that were written
immediately after an `ExportTableToPointInTime` CloudTrail event.

### 2. CloudTrail S3 Data Events
Enable CloudTrail data events on the export bucket with `s3:PutObject` scope.
This surfaces writes even from service principals. Correlate:
- `eventName: PutObject` from `userIdentity.invokedBy: dynamodb.amazonaws.com`
- Timestamp within minutes of the `ExportTableToPointInTime` control event
- Key prefix matching the export path pattern

### 3. Amazon GuardDuty
GuardDuty finding types relevant to this technique:
- `Policy:S3/BucketBlockPublicAccessDisabled` -- if attacker modifies bucket ACLs
  to later exfiltrate the export data externally
- `Discovery:S3/BucketEnumeration` -- if attacker also enumerates S3 buckets
- `UnauthorizedAccess:IAMUser/MaliciousIPCaller` -- if source IP is threat-intel-flagged

GuardDuty does NOT generate a finding specifically for `ExportTableToPointInTime`.

### 4. AWS Config Rules
A custom Config rule can alert when any S3 bucket receives a cross-service write
from `dynamodb.amazonaws.com` to a bucket not tagged as an approved backup destination.

### 5. VPC Flow Logs
Not applicable -- DynamoDB export is a fully managed AWS-internal data path with
no traffic traversing a customer VPC.

## Correlation Pivot

Use the `ExportArn` from the `ExportTableToPointInTime` CloudTrail response to
anchor the S3 server access log timeline:

```
ExportArn: arn:aws:dynamodb:{region}:{account}:table/{table}/export/{timestamp}
S3 path:   {s3_prefix}/AWSDynamoDB/{export_id}/manifest-files.json
```

Match the export ID component of the ARN against S3 key prefixes in server access
logs to confirm data landed in the bucket.
