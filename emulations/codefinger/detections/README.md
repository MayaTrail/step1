# Codefinger Detection Package

Platform: AWS CloudTrail
Generated: 2026-05-13
SIEM target: Microsoft Sentinel (AWSCloudTrail table)

All techniques are control_plane and produce CloudTrail audit events.

## Files

| Technique | SIGMA | KQL | Level |
|---|---|---|---|
| T1078.004 Valid Accounts: Cloud Accounts | sigma_t1078.004.yml | kql_t1078.004.kql | High |
| T1530 Data from Cloud Storage | sigma_t1530.yml | kql_t1530.kql | Medium |
| T1486 Data Encrypted for Impact | sigma_t1486.yml | kql_t1486.kql | High |
| T1485 Data Destruction | sigma_t1485.yml | kql_t1485.kql | High/Critical |
| T1490 Inhibit System Recovery | sigma_t1490.yml | kql_t1490.kql | Critical |

## Kill Chain Correlation

The highest-fidelity detection is the **full kill chain sequence** in `kql_t1490.kql` Query 4:
- SSE-C PutObject (T1486) +
- PutBucketLifecycleConfiguration (T1485) +
- PutBucketVersioning Suspended (T1490) +
- DeleteObjectVersion (T1490)

Any 3-of-4 signals from the same IAM principal within 2 hours = high-confidence Codefinger match.

## Tuning Notes

- Replace `svc-terraform`, `svc-cicd`, `svc-backup` filters with actual service account names.
- Adjust ListObjects burst threshold (default: >20 in 15 min) to org CloudTrail baseline.
- The lifecycle expiry parser (`ExpiryDaysInt <= 7`) requires RequestParameters to be ingested
  as a string; verify your connector preserves the raw JSON body.
- GuardDuty findings complement these rules: enable S3 Protection and look for
  `Impact:S3/MaliciousIPCaller.Custom` and `Discovery:S3/MaliciousIPCaller`.
