# Detection Note: T1491.002 - External Defacement - PutObject (Data Plane)

## Technique Step
Step 3: Upload defacement index.html to the attacker-claimed bucket via S3 PutObject.

## Why No Audit Log

PutObject is an S3 **data-plane** operation. It does not generate a CloudTrail
management event by default. No SIGMA rule or KQL query over the management-event
stream will detect this step.

## Detection Alternatives

### AWS S3 Data Event Logging (CloudTrail)
Enable S3 data event logging for the bucket or account-wide to capture PutObject
in CloudTrail. When enabled, the event will appear with:
- `eventName: PutObject`
- `eventSource: s3.amazonaws.com`
- `requestParameters.bucketName: <attacker-claimed-bucket>`
- `requestParameters.key: index.html`

### S3 Server Access Logs
Enable server access logging on monitored buckets. A PUT to `index.html` on a
newly created bucket that also has website hosting enabled is anomalous.

### EventBridge + S3 Event Notifications
Configure an S3 bucket notification for `s3:ObjectCreated:Put` events delivered
to EventBridge or an SNS topic. Alert on PUT events to buckets that were created
by non-IaC principals and have website hosting enabled (cross-reference with
PutBucketWebsite CloudTrail events).

### AWS Config Rule: s3-bucket-public-access-prohibited
If the attacker removes the bucket's Block Public Access settings to allow public
reads of the defacement content, Config will record a non-compliant resource
evaluation. This fires on the control-plane change, not the PutObject itself.

### GuardDuty
No native GuardDuty finding covers PutObject to an attacker-owned bucket.
GuardDuty S3 Protection covers anomalous access to *existing* monitored buckets,
not newly created attacker buckets.

### Network / CDN
If DNS traffic to the victim subdomain is monitored (WAF, CloudFront access logs,
external DNS monitoring), a spike in requests to the defaced endpoint after the
CNAME takeover is observable at the network layer.
