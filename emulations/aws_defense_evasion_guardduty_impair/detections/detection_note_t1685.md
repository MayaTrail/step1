# Detection Note: T1685 - S3 Trusted-IP Artifact Staging (Data Plane)

**Emulation step:** 3 - S3 PutObject of trusted_ip_list.txt to security-mimicking bucket  
**audit_visible:** false  
**CloudTrail data event visibility:** NOT recorded by default (S3 data events require explicit CloudTrail configuration)

## Why This Step Has No Default Audit Log

`s3:PutObject` is an S3 data-plane operation. AWS CloudTrail management events (the default trail)
do NOT record S3 object-level API calls. The PutObject in this step will not appear in CloudTrail
unless the trail has **S3 data event logging** explicitly enabled for the target bucket.

## Detection Alternatives

### 1. S3 Server Access Logs (bucket-level)
Enable server access logging on the bucket receiving the trusted-IP file. Each PutObject will
produce a log entry in the designated access-log bucket. Look for:
- `REST.PUT.OBJECT` operations on `trusted_ip_list.txt` or similarly named keys
- Source IP / requester ARN that does not match expected security-automation principals

### 2. CloudTrail S3 Data Events (requires opt-in)
If the trail has S3 data event logging enabled for the impair bucket:
```
eventSource: s3.amazonaws.com
eventName: PutObject
requestParameters.bucketName: <bucket-containing-trusted-ip>
requestParameters.key: trusted_ip_list.txt
```
Correlate the caller identity with the assumed-role session from step 1 (AssumeRole into
`atomic-guardduty-impair-attacker-role`) to confirm the attack chain.

### 3. GuardDuty CreateIPSet Location Field (indirect)
Even without S3 logging, the GuardDuty `CreateIPSet` CloudTrail event (step 4) records the
S3 URI of the IP list in `requestParameters.location`. Alert when this location references
a bucket that is not the organization's approved threat-intel bucket. This provides indirect
evidence that an adversary staged a file in an unauthorized bucket.

### 4. AWS Config Rules
An AWS Config rule evaluating `s3:BucketPolicy` or object-level ACLs cannot directly detect
a PutObject, but it can detect if the bucket's policy was modified to allow unexpected
principals write access -- a precondition for this staging technique.

### 5. VPC Flow Logs / Network-Level
If the attacker is operating from a known IP range, VPC Flow Logs may show HTTPS traffic
(port 443) to `s3.<region>.amazonaws.com` from the attacker's compute resource. This is
a weak signal in isolation but corroborates host-level IOCs.

## Recommended Remediation Action
Enable S3 CloudTrail data events on all buckets containing security-sensitive content
(threat-intel lists, GuardDuty IPSet sources, detector configurations). The cost is low
for low-churn buckets and the coverage gap is significant for this attack class.
