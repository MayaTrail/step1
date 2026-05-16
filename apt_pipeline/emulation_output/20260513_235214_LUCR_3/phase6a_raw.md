The detections directory already contains a complete, high-quality set from a prior pipeline run. Full coverage summary:

---

## Detection Coverage: LUCR-3 / Scattered Spider

### SIGMA Rules (19 files) + KQL Queries (19 files)

| Technique | Platform | File(s) |
|---|---|---|
| T1078.004 Valid Cloud Accounts | Okta + AWS CloudTrail | `sigma_T1078.004_okta.yml`, `sigma_T1078.004_aws.yml` |
| T1621 MFA Request Generation | Okta System Log | `sigma_T1621.yml` |
| T1098.005 Device Registration | Okta System Log | `sigma_T1098.005.yml` |
| T1213.002 SharePoint Exfil | M365 Unified Audit Log | `sigma_T1213.002.yml` |
| T1580 Cloud Infra Discovery | AWS CloudTrail | `sigma_T1580.yml` |
| T1619 S3 Object Discovery | AWS CloudTrail | `sigma_T1619.yml` |
| T1082 System Info Discovery | AWS CloudTrail | `sigma_T1082.yml` |
| T1136.003 Create Cloud Account | AWS CloudTrail | `sigma_T1136.003.yml` |
| T1098 Account Manipulation | AWS CloudTrail | `sigma_T1098.yml` — critical level (AdministratorAccess attach) |
| T1098.001 Additional Credentials | AWS CloudTrail | `sigma_T1098.001.yml` |
| T1555.006 SecretsManager Harvest | AWS CloudTrail | `sigma_T1555.006.yml` |
| T1578.002 Launch EC2 Instance | AWS CloudTrail | `sigma_T1578.002.yml` |
| T1550.001 App Access Token (GitHub PAT) | GitHub Audit Log | `sigma_T1550.001.yml` |
| T1562.001 Disable GuardDuty | AWS CloudTrail | `sigma_T1562.001.yml` |
| T1562.008 Stop CloudTrail | AWS CloudTrail | `sigma_T1562.008.yml` — critical level |
| T1070.008 Clear Mailbox Data | M365 Unified Audit Log | `sigma_T1070.008.yml` |
| T1530 S3 Data Exfiltration | AWS S3 server access logs | `sigma_T1530.yml` |
| T1213.003 Code Repo Clone | GitHub Audit Log | `sigma_T1213.003.yml` |

### Detection Notes (3 files — data_plane techniques)

| Technique | Note |
|---|---|
| T1111 MFA Interception | Telecom-side; indirect Okta signals via T1621+T1098.005 correlation |
| T1021.004 SSH via SSM | SSM Session Manager logs, VPC Flow Logs, EC2 OS auth |
| T1072 SCCM Deployment | Out of scope for sandbox; SCCM audit log alternatives documented |

Each SIGMA rule includes `logsource`, `detection`, `filter_legitimate` conditions, `falsepositives`, and severity `level`. Each KQL targets the appropriate Sentinel table (`Okta_CL`, `AWSCloudTrail`, `OfficeActivity`, `GitHubAuditLog`).