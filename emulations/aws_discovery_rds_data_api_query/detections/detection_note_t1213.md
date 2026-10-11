# Detection Note: T1213 - RDS Data API ExecuteStatement (Data Plane Gap)

## Visibility Gap

Steps 2 and 3 of this emulation (SHOW TABLES enumeration and SELECT * exfiltration via
rds-data:ExecuteStatement) generate **no CloudTrail events by default**. ExecuteStatement
is a CloudTrail **data event** for the resource type `AWS::RDS::DBCluster`. Data events
must be explicitly enabled per-trail and incur additional CloudTrail costs.

Without data events, an adversary can enumerate schemas, dump entire tables, and exfiltrate
PII over HTTPS using only stolen IAM static keys — and leave **zero trace** in the default
CloudTrail configuration.

## How to Enable Coverage

### CloudTrail Data Events (primary fix)
Enable data events for RDS clusters in your CloudTrail trail:

```
CloudTrail Console -> Trails -> <your trail> -> Edit
  -> Data events tab
  -> Add data event source: RDS
  -> Log selector: Log all clusters (or target specific cluster ARNs)
```

Once enabled, `rds-data:ExecuteStatement` appears as a data event with:
- `eventSource`: `rds-data.amazonaws.com`
- `eventName`: `ExecuteStatement`
- `requestParameters.sql`: the raw SQL statement (the full SELECT/SHOW query is logged)
- `resources[].ARN`: the Aurora cluster ARN

The SIGMA rule `sigma_T1213_ExecuteStatement.yml` and KQL `kql_T1213_ExecuteStatement.kql`
in this directory will fire once data events are active.

## Detection Alternatives (No Data Events Required)

### GuardDuty - CredentialAccess:RDS/AnomalousBehavior
GuardDuty ML baseline detects unusual Data API callers once an access baseline is established
(typically 2-4 weeks of normal application traffic). This finding fires when:
- A principal that has never called ExecuteStatement starts issuing queries
- Query volume from a principal deviates significantly from their historical pattern
- A long-dormant IAM user calls the Data API

**Limitation**: New accounts or environments with no established baseline will not trigger this.

### GuardDuty - CredentialAccess:Secrets/AnomalousBehavior
Fires on the Step 1 GetSecretValue call (management event, always visible) when the
caller deviates from the normal access baseline for that secret.

### Amazon Macie (downstream detection)
If the exfiltration pipeline writes query results to S3 (common pattern for bulk dumps),
Macie can detect PII (SSN, email, salary data) in the written objects and raise a
sensitive data discovery finding. This catches the exfil artifact, not the API call itself.

### CloudWatch Metrics Alarm
Aurora publishes `DatabaseConnections` and custom Data API metrics. A spike in
`RDSDataAPICallsSucceeded` from an unusual source IP can be alarmed on, though this
requires custom metric filters and is noisy in multi-tenant environments.

### VPC Flow Logs
The RDS Data API endpoint is public HTTPS - VPC Flow Logs do **not** capture this traffic.
The attacker never establishes a VPC network connection to the Aurora cluster. VPC-based
network detection is not applicable for this attack path.

## Summary Table

| Detection Method | Step 1 (GetSecretValue) | Step 2 (SHOW TABLES) | Step 3 (SELECT *) | Always On? |
|---|---|---|---|---|
| CloudTrail management events | YES | NO | NO | Yes |
| CloudTrail data events (RDS) | n/a | YES | YES | No - must enable |
| GuardDuty RDS/AnomalousBehavior | n/a | Partial (needs baseline) | Partial (needs baseline) | Yes (after baseline) |
| GuardDuty Secrets/AnomalousBehavior | Partial (needs baseline) | NO | NO | Yes (after baseline) |
| Macie (downstream S3) | NO | NO | Partial (if written to S3) | Yes (on covered buckets) |
| VPC Flow Logs | NO | NO | NO | Not applicable |
