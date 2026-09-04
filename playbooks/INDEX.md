# Index — 115 AWS incident-response playbooks

115 playbooks across 25 AWS services. One playbook per detection use case.

Each row links to the six-phase response procedure. Detection rules live beside it in
`<playbook>/detections/`.

---

## alb — 3 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [alb.credential-access.alb-not-using-secure-listener](playbooks/alb.credential-access.alb-not-using-secure-listener/PLAYBOOK.md) | Credential access / collection | T1557 | High |
| [alb.credential-access.multiple-failed-authentication](playbooks/alb.credential-access.multiple-failed-authentication/PLAYBOOK.md) | Credential access | T1110 | High for a JWT signature that does not v |
| [alb.stealth.no-logs-from-aws-alb](playbooks/alb.stealth.no-logs-from-aws-alb/PLAYBOOK.md) | Defense impairment | T1685.002 | High |

## bedrock — 3 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [bedrock.discovery.high-number-of-invocation-errors](playbooks/bedrock.discovery.high-number-of-invocation-errors/PLAYBOOK.md) | Discovery | T1526 | High |
| [bedrock.impact.high-invocation-count](playbooks/bedrock.impact.high-invocation-count/PLAYBOOK.md) | Resource hijacking | T1496 | High |
| [bedrock.stealth.low-invocation-count](playbooks/bedrock.stealth.low-invocation-count/PLAYBOOK.md) | Defense impairment | T1685.002 | High |

## cloudtrail — 5 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [cloudtrail.discovery.audit-configuration-accessed](playbooks/cloudtrail.discovery.audit-configuration-accessed/PLAYBOOK.md) | Discovery | T1654 | Informational for a single read; medium  |
| [cloudtrail.impact.trail-deleted](playbooks/cloudtrail.impact.trail-deleted/PLAYBOOK.md) | Defence evasion | T1685.002 | Critical for a multi-Region or organizat |
| [cloudtrail.stealth.no-logs-received](playbooks/cloudtrail.stealth.no-logs-received/PLAYBOOK.md) | Defence evasion | T1685.002 | Critical when the destination bucket or  |
| [cloudtrail.stealth.trail-logging-stopped](playbooks/cloudtrail.stealth.trail-logging-stopped/PLAYBOOK.md) | Defence evasion | T1685.002 | Critical |
| [cloudtrail.stealth.trail-modified](playbooks/cloudtrail.stealth.trail-modified/PLAYBOOK.md) | Defence evasion | T1685.002 | Critical when global service events or t |

## cognito — 5 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [cognito.credential-access.multiple-failed-administrative-authentication-attempts](playbooks/cognito.credential-access.multiple-failed-administrative-authentication-attempts/PLAYBOOK.md) | Credential access | T1110.001 | High |
| [cognito.credential-access.multiple-failed-authentication-attempts-from-single-source](playbooks/cognito.credential-access.multiple-failed-authentication-attempts-from-single-source/PLAYBOOK.md) | Credential access | T1110.003 | Medium for the volume alert, against the |
| [cognito.impact.identity-pool-deletion-detected](playbooks/cognito.impact.identity-pool-deletion-detected/PLAYBOOK.md) | Data destruction / Account access removal | T1485 | High, for a single deletion as much as f |
| [cognito.impact.user-pool-deletion-protection-disabled-followed-by-user-po](playbooks/cognito.impact.user-pool-deletion-protection-disabled-followed-by-user-po/PLAYBOOK.md) | Data destruction / Account access removal | T1485 | Critical |
| [cognito.persistence.identity-pool-configured-to-allow-unauthenticated-access](playbooks/cognito.persistence.identity-pool-configured-to-allow-unauthenticated-access/PLAYBOOK.md) | Persistence / Initial access | T1098 | Critical where a role is attached; High  |

## dynamodb — 8 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [dynamodb.collection.table-scanned](playbooks/dynamodb.collection.table-scanned/PLAYBOOK.md) | Collection | T1530 | High when reads span three or more table |
| [dynamodb.defense-evasion.table-configuration-modified](playbooks/dynamodb.defense-evasion.table-configuration-modified/PLAYBOOK.md) | Defence evasion | T1685.002 | High for Streams disabled or an encrypti |
| [dynamodb.impact.backup-was-deleted](playbooks/dynamodb.impact.backup-was-deleted/PLAYBOOK.md) | Recovery capability destruction | T1490 — verified live 2026-08-29, and the source rule's own mapping, which is **correct** | High for a non-pipeline deletion, Critic |
| [dynamodb.impact.backup-was-listed](playbooks/dynamodb.impact.backup-was-listed/PLAYBOOK.md) | Discovery | T1580 | Informational on its own; High to Critic |
| [dynamodb.impact.multiple-tables-created](playbooks/dynamodb.impact.multiple-tables-created/PLAYBOOK.md) | Impact | T1496 | Medium for volume; high when a newly cre |
| [dynamodb.impact.multiple-tables-deleted](playbooks/dynamodb.impact.multiple-tables-deleted/PLAYBOOK.md) | Data destruction / Availability | T1485 | High for a single deletion as much as fo |
| [dynamodb.impact.table-items-modified-or-destroyed](playbooks/dynamodb.impact.table-items-modified-or-destroyed/PLAYBOOK.md) | Impact | T1485 | Critical for removal of point-in-time re |
| [dynamodb.stealth.deletion-protection-disabled](playbooks/dynamodb.stealth.deletion-protection-disabled/PLAYBOOK.md) | Defensive control removal / pre-destruction staging | T1685 | High for the disable alone, Critical onc |

## ec2 — 1 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [ec2.credential-access.imds-credential-theft](playbooks/ec2.credential-access.imds-credential-theft/PLAYBOOK.md) | Credential access / Unsecured credentials | T1552.005, T1190 | High, P0 once off-instance use is confir |

## ecr — 6 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [ecr.collection.excessive-images-pulled](playbooks/ecr.collection.excessive-images-pulled/PLAYBOOK.md) | Collection | T1530 | High when pulls span five or more distin |
| [ecr.impact.images-destroyed](playbooks/ecr.impact.images-destroyed/PLAYBOOK.md) | Impact | T1485 | Critical for a repository deletion or de |
| [ecr.privilege-escalation.repository-policy-applied](playbooks/ecr.privilege-escalation.repository-policy-applied/PLAYBOOK.md) | Account manipulation | T1098 | High |
| [ecr.stealth.image-scanning-disabled](playbooks/ecr.stealth.image-scanning-disabled/PLAYBOOK.md) | Defence evasion | T1685 | High |
| [ecr.stealth.image-tag-overwrite-enabled](playbooks/ecr.stealth.image-tag-overwrite-enabled/PLAYBOOK.md) | Software supply-chain tampering | T1525 | High, against the source rule's P4 — the |
| [ecr.stealth.malicious-image-pushed](playbooks/ecr.stealth.malicious-image-pushed/PLAYBOOK.md) | Persistence | T1525 | High |

## ecs — 5 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [ecs.impact.updateservice-with-high-desiredcount](playbooks/ecs.impact.updateservice-with-high-desiredcount/PLAYBOOK.md) | Resource hijacking | T1496.001 | High, against the source's P3 |
| [ecs.initial-access.command-executed-inside-a-container](playbooks/ecs.initial-access.command-executed-inside-a-container/PLAYBOOK.md) | Execution + Credential access | T1609 | High, P0 once task-role activity is obse |
| [ecs.stealth.cluster-is-deleted](playbooks/ecs.stealth.cluster-is-deleted/PLAYBOOK.md) | Indicator removal / Infrastructure destruction | T1070 | High, and the source's P1 is close to ri |
| [ecs.stealth.service-is-created](playbooks/ecs.stealth.service-is-created/PLAYBOOK.md) | Execution / Persistence | T1610 | High, against the source's P3 |
| [ecs.stealth.service-is-deleted](playbooks/ecs.stealth.service-is-deleted/PLAYBOOK.md) | Availability / Indicator removal | T1489 | High, against the source's P3 |

## eks — 5 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [eks.lateral-movement.unauthorized-user-trying-to-get-secrets](playbooks/eks.lateral-movement.unauthorized-user-trying-to-get-secrets/PLAYBOOK.md) | Credential access | T1552.007 | High on a successful read by a principal |
| [eks.persistence.flow-alert---suspicious-operation-detected-from-service-ac](playbooks/eks.persistence.flow-alert---suspicious-operation-detected-from-service-ac/PLAYBOOK.md) | Persistence / privilege escalation | T1098.006 | High — and critical once RBAC is written |
| [eks.privilege-escalation.anomalous-request-detected](playbooks/eks.privilege-escalation.anomalous-request-detected/PLAYBOOK.md) | Execution | T1609 | High |
| [eks.privilege-escalation.flow-alert---cluster-admin-access-granted-after-multiple-u](playbooks/eks.privilege-escalation.flow-alert---cluster-admin-access-granted-after-multiple-u/PLAYBOOK.md) | Privilege escalation + Persistence | T1098.006 | High, P0 on the correlated pair |
| [eks.stealth.user-deleted-log-events](playbooks/eks.stealth.user-deleted-log-events/PLAYBOOK.md) | Defense impairment | T1685.002 | High |

## guardduty — 2 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [guardduty.stealth.no-logs-from-amazon-guardduty](playbooks/guardduty.stealth.no-logs-from-amazon-guardduty/PLAYBOOK.md) | Defense impairment | T1685 | High |
| [guardduty.unmapped.critical-severity-alert](playbooks/guardduty.unmapped.critical-severity-alert/PLAYBOOK.md) | Detection triage | T1078 | Critical for the 9 |

## iam — 5 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [iam.persistence.role-trust-backdoor](playbooks/iam.persistence.role-trust-backdoor/PLAYBOOK.md) | Persistence / Account manipulation | T1098.001 **and T1098.003** | High, P0 when the trust names a foreign  |
| [iam.privilege-escalation.admin-policy-attached](playbooks/iam.privilege-escalation.admin-policy-attached/PLAYBOOK.md) | Privilege escalation | T1098.003 | Critical for an administrative policy or |
| [iam.privilege-escalation.default-policy-version-reverted](playbooks/iam.privilege-escalation.default-policy-version-reverted/PLAYBOOK.md) | Privilege escalation | T1098.003 | High for a single activation; critical w |
| [iam.privilege-escalation.inline-policy-grant](playbooks/iam.privilege-escalation.inline-policy-grant/PLAYBOOK.md) | Privilege escalation / Account manipulation | T1098.003 | High, P0 for the self-grant and uncondit |
| [iam.privilege-escalation.policy-version-overly-permissive](playbooks/iam.privilege-escalation.policy-version-overly-permissive/PLAYBOOK.md) | Privilege escalation | T1098.003 | Critical when the administrative version |

## kms — 5 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [kms.impact.key-created](playbooks/kms.impact.key-created/PLAYBOOK.md) | Impact | T1486 | Critical when imported key material is d |
| [kms.impact.key-policy-access-removed](playbooks/kms.impact.key-policy-access-removed/PLAYBOOK.md) | Impact | T1486 | Critical when the lockout safety check w |
| [kms.impact.kms-key-disabled](playbooks/kms.impact.kms-key-disabled/PLAYBOOK.md) | Availability impact | T1489 | High |
| [kms.impact.kms-key-scheduled-deletion](playbooks/kms.impact.kms-key-scheduled-deletion/PLAYBOOK.md) | Destructive impact | T1485, T1486 | Critical |
| [kms.impact.multiple-kms-keys-scheduled-deletion](playbooks/kms.impact.multiple-kms-keys-scheduled-deletion/PLAYBOOK.md) | Impact / data destruction | T1485 | High for a single key, Critical for seve |

## lambda — 3 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [lambda.defense-evasion.function-configuration-modified](playbooks/lambda.defense-evasion.function-configuration-modified/PLAYBOOK.md) | Defence evasion and privilege escalation | T1578.005 | High for a handler or layer change and f |
| [lambda.persistence.function-code-overwritten](playbooks/lambda.persistence.function-code-overwritten/PLAYBOOK.md) | Persistence | T1525 | High |
| [lambda.persistence.resource-policy-backdoor](playbooks/lambda.persistence.resource-policy-backdoor/PLAYBOOK.md) | Persistence / Account manipulation | T1098 | High, P0 |

## netfw — 3 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [netfw.stealth.no-logs-from-aws-network-firewall-in-4-hours](playbooks/netfw.stealth.no-logs-from-aws-network-firewall-in-4-hours/PLAYBOOK.md) | Defense impairment | T1685.002 | High |
| [netfw.unmapped.high-severity-alert-detected](playbooks/netfw.unmapped.high-severity-alert-detected/PLAYBOOK.md) | Detection triage | T1071 | High when the traffic was not blocked |
| [netfw.unmapped.suspicious-low-throughput-egress](playbooks/netfw.unmapped.suspicious-low-throughput-egress/PLAYBOOK.md) | Exfiltration and command-and-control | T1071 | High once the destination is unexplained |

## rds — 5 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [rds.exfiltration.database-instancecluster-made-public](playbooks/rds.exfiltration.database-instancecluster-made-public/PLAYBOOK.md) | Exposure / Initial access precondition | T1578.005 | High outside the database-lifecycle pipe |
| [rds.exfiltration.rds-snapshot-export](playbooks/rds.exfiltration.rds-snapshot-export/PLAYBOOK.md) | Data exfiltration | T1567.002 | High for an export by a principal outsid |
| [rds.exfiltration.snapshot-made-public](playbooks/rds.exfiltration.snapshot-made-public/PLAYBOOK.md) | Data exfiltration | T1537 | Critical where the value added is `all`, |
| [rds.impact.rds-security-group-creation-or-deletion-legacy](playbooks/rds.impact.rds-security-group-creation-or-deletion-legacy/PLAYBOOK.md) | Firewall change in front of a database | T1686.001 | Medium for a legacy DB security group ca |
| [rds.stealth.database-instancecluster-was-created-with-no-encryption](playbooks/rds.stealth.database-instancecluster-was-created-with-no-encryption/PLAYBOOK.md) | Control failure creating an exfiltration precondition | T1578.002 | Medium for one database, High for three  |

## route53 — 5 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [route53.initial-access.amazon-route53-audit-domain-transfer-lock-disabled-followe](playbooks/route53.initial-access.amazon-route53-audit-domain-transfer-lock-disabled-followe/PLAYBOOK.md) | Resource development / infrastructure loss | T1584.001 | Critical |
| [route53.initial-access.caa-record-created-or-updated](playbooks/route53.initial-access.caa-record-created-or-updated/PLAYBOOK.md) | Defense impairment | T1685 | High, and critical when the published va |
| [route53.stealth.dns-zone-deleted](playbooks/route53.stealth.dns-zone-deleted/PLAYBOOK.md) | Destruction of availability | T1485 — verified live 2026-08-29. | High for a deletion by a principal outsi |
| [route53.stealth.multiple-dns-zones-deleted-by-a-single-user](playbooks/route53.stealth.multiple-dns-zones-deleted-by-a-single-user/PLAYBOOK.md) | Destruction of availability at scale | T1485 — verified live 2026-08-29. | Critical |
| [route53.stealth.ns-record-created-or-updated](playbooks/route53.stealth.ns-record-created-or-updated/PLAYBOOK.md) | Resource development | T1584.001 | High, and critical when the nameservers  |

## route53dns — 3 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [route53dns.exfiltration.suspicious-query-with-base64-encoded-string](playbooks/route53dns.exfiltration.suspicious-query-with-base64-encoded-string/PLAYBOOK.md) | Exfiltration and command-and-control over DNS | T1048.003 | High |
| [route53dns.privilege-escalation.suspicious-aws-metadata-query](playbooks/route53dns.privilege-escalation.suspicious-aws-metadata-query/PLAYBOOK.md) | Credential access | T1552.005 | Critical when the answer is link-local |
| [route53dns.stealth.no-logs-from-amazon-route53-dns-query](playbooks/route53dns.stealth.no-logs-from-amazon-route53-dns-query/PLAYBOOK.md) | Defense impairment | T1685.002 | High |

## s3 — 7 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [s3.exfiltration.bucket-acl-configured](playbooks/s3.exfiltration.bucket-acl-configured/PLAYBOOK.md) | Collection | T1530 | High |
| [s3.exfiltration.bucket-policy-made-public](playbooks/s3.exfiltration.bucket-policy-made-public/PLAYBOOK.md) | Collection | T1530 | High |
| [s3.exfiltration.public-access-block-deleted](playbooks/s3.exfiltration.public-access-block-deleted/PLAYBOOK.md) | Collection precondition | T1530 | High for a bucket, Critical for the acco |
| [s3.exfiltration.public-access-block-removed](playbooks/s3.exfiltration.public-access-block-removed/PLAYBOOK.md) | Collection | T1530 | High when an immediate-effect flag is lo |
| [s3.impact.bucket-policy-deleted](playbooks/s3.impact.bucket-policy-deleted/PLAYBOOK.md) | Collection or availability impact, and the event cannot say which | T1530 | Medium for one deletion, because the dir |
| [s3.stealth.access-logging-disabled](playbooks/s3.stealth.access-logging-disabled/PLAYBOOK.md) | Defence evasion | T1685.002 | Medium on its own, high when it precedes |
| [s3.stealth.public-access-block-created-or-modified](playbooks/s3.stealth.public-access-block-created-or-modified/PLAYBOOK.md) | Defence evasion | T1070 | Informational as a standalone event; hig |

## secretsmanager — 7 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user](playbooks/secretsmanager.credential-access.high-number-of-secrets-retrievals-from-single-user/PLAYBOOK.md) | Credential access / bulk secret disclosure | T1555.006 — Credentials from Password Stores: Cloud Secrets Management Stores | High |
| [secretsmanager.discovery.access-repeatedly-denied](playbooks/secretsmanager.discovery.access-repeatedly-denied/PLAYBOOK.md) | Discovery | T1526 | Critical when a denial burst accompanies |
| [secretsmanager.discovery.secrets-enumerated](playbooks/secretsmanager.discovery.secrets-enumerated/PLAYBOOK.md) | Discovery | T1526 | Critical if any `GetSecretValue` succeed |
| [secretsmanager.impact.secret-deleted](playbooks/secretsmanager.impact.secret-deleted/PLAYBOOK.md) | Impact | T1485 | Critical when `ForceDeleteWithoutRecover |
| [secretsmanager.persistence.rotation-disabled](playbooks/secretsmanager.persistence.rotation-disabled/PLAYBOOK.md) | Persistence | T1098 | Critical when rotation is cancelled acro |
| [secretsmanager.persistence.secret-value-replaced](playbooks/secretsmanager.persistence.secret-value-replaced/PLAYBOOK.md) | Persistence | T1556 | High when `AWSCURRENT` is moved to an ex |
| [secretsmanager.privilege-escalation.resource-based-permission-policy-attached-to-a-secret](playbooks/secretsmanager.privilege-escalation.resource-based-permission-policy-attached-to-a-secret/PLAYBOOK.md) | Privilege escalation / persistence | T1098 — Account Manipulation | High |

## sg — 2 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [sg.exfiltration.egress-rule-opened](playbooks/sg.exfiltration.egress-rule-opened/PLAYBOOK.md) | Firewall weakening on the outbound path | T1686.001 | High when a narrowed group is re-widened |
| [sg.initial-access.remote-management-open](playbooks/sg.initial-access.remote-management-open/PLAYBOOK.md) | Firewall weakening | T1686.001 | Critical for remote-management ports or  |

## sns — 7 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [sns.collection.sns-topic-was-created-with-public-publish-permissions](playbooks/sns.collection.sns-topic-was-created-with-public-publish-permissions/PLAYBOOK.md) | Resource-policy exposure | T1098, T1565.002 | High |
| [sns.collection.sns-topic-was-created-with-public-subscribe-permissions](playbooks/sns.collection.sns-topic-was-created-with-public-subscribe-permissions/PLAYBOOK.md) | Resource-policy exposure | T1213, T1098 | High |
| [sns.impact.a-less-secure-server-side-encryption-policy-created](playbooks/sns.impact.a-less-secure-server-side-encryption-policy-created/PLAYBOOK.md) | Defense impairment / weakened encryption | T1600 | Medium for the single event, High once t |
| [sns.impact.server-side-encryption-for-aws-sns-topics-was-disabled](playbooks/sns.impact.server-side-encryption-for-aws-sns-topics-was-disabled/PLAYBOOK.md) | Defense impairment / weakened encryption | T1600 | High, against the source rule's P4 |
| [sns.initial-access.flow-alert---possible-smishing-observed](playbooks/sns.initial-access.flow-alert---possible-smishing-observed/PLAYBOOK.md) | Service abuse for outbound phishing | T1566, T1584.006, T1526 | High, against the source rule's P2 |
| [sns.persistence.topic-policy-modified](playbooks/sns.persistence.topic-policy-modified/PLAYBOOK.md) | Persistence | T1098 | Critical for a wildcard principal, or an |
| [sns.stealth.topic-deleted](playbooks/sns.stealth.topic-deleted/PLAYBOOK.md) | Defence impairment | T1685 | Critical when the topic carried alerts o |

## sqs — 5 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [sqs.collection.an-sqs-queue-attributes-were-changed](playbooks/sqs.collection.an-sqs-queue-attributes-were-changed/PLAYBOOK.md) | Account manipulation / Collection | T1098 | High for the wildcard and cross-account  |
| [sqs.impact.server-side-encryption-for-aws-sqs-queue-was-disabled](playbooks/sqs.impact.server-side-encryption-for-aws-sqs-queue-was-disabled/PLAYBOOK.md) | Defence impairment | T1600 | High, against the source rule's P4 |
| [sqs.stealth.a-queue-was-deleted](playbooks/sqs.stealth.a-queue-was-deleted/PLAYBOOK.md) | Data destruction / Availability | T1485 | High, for a single deletion as much as f |
| [sqs.stealth.a-queue-was-purged](playbooks/sqs.stealth.a-queue-was-purged/PLAYBOOK.md) | Data destruction / Indicator removal | T1485 | High, against the source rule's P3 — arg |
| [sqs.stealth.excessive-queue-creation](playbooks/sqs.stealth.excessive-queue-creation/PLAYBOOK.md) | Resource hijacking / Staging | T1496 | Medium for the volume case — the source' |

## ssm — 5 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [ssm.credential-access.high-number-of-ssm-parameters-retrieval](playbooks/ssm.credential-access.high-number-of-ssm-parameters-retrieval/PLAYBOOK.md) | Credential access | T1555.006 | High |
| [ssm.discovery.excessive-document-creation-detected](playbooks/ssm.discovery.excessive-document-creation-detected/PLAYBOOK.md) | Execution / cloud administration command | T1651 | High for a write to `SSM-SessionManagerR |
| [ssm.discovery.excessive-parameter-creation-detected](playbooks/ssm.discovery.excessive-parameter-creation-detected/PLAYBOOK.md) | Stored data manipulation | T1565.001 | High for an overwrite of an existing par |
| [ssm.impact.parameter-deletion-detected](playbooks/ssm.impact.parameter-deletion-detected/PLAYBOOK.md) | Data destruction | T1485 | High, and P0 at five or more deletions i |
| [ssm.initial-access.excessive-failed-document-retrieval-attempts](playbooks/ssm.initial-access.excessive-failed-document-retrieval-attempts/PLAYBOOK.md) | Cloud service discovery | T1526 | Medium for the enumeration alone — it is |

## vpc — 5 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [vpc.impact.syn-flood-detection](playbooks/vpc.impact.syn-flood-detection/PLAYBOOK.md) | Impact / availability | T1498 | High |
| [vpc.initial-access.critical-database-exposure-to-public-internet](playbooks/vpc.initial-access.critical-database-exposure-to-public-internet/PLAYBOOK.md) | Initial access | T1190 | Critical once a connection is accepted |
| [vpc.initial-access.possible-ssrf-attempt-hit-to-169254169254](playbooks/vpc.initial-access.possible-ssrf-attempt-hit-to-169254169254/PLAYBOOK.md) | Exploitation of a public-facing application, used to reach hosts and ports the application itse | T1190 | High |
| [vpc.lateral-movement.incoming-requests-over-remote-service-ports-accepted-from](playbooks/vpc.lateral-movement.incoming-requests-over-remote-service-ports-accepted-from/PLAYBOOK.md) | External remote services | T1021 | High, and critical when the source also  |
| [vpc.stealth.no-logs-from-amazon-vpc-flow-logs](playbooks/vpc.stealth.no-logs-from-amazon-vpc-flow-logs/PLAYBOOK.md) | Defense impairment | T1685.002 | High |

## waf — 5 playbook(s)

| Playbook | Covers | ATT&CK | Severity |
|---|---|---|---|
| [waf.credential-access.crs-ssrf-ec2-metadata](playbooks/waf.credential-access.crs-ssrf-ec2-metadata/PLAYBOOK.md) | Credential access attempt at the edge | T1552.005 | High where the terminating action is `AL |
| [waf.initial-access.cve-log4j-rce-attempt](playbooks/waf.initial-access.cve-log4j-rce-attempt/PLAYBOOK.md) | Exploitation attempt against a public-facing application | T1190 | High where the terminating action is `AL |
| [waf.initial-access.known-bad-ip-with-allowed-web-attack-detected](playbooks/waf.initial-access.known-bad-ip-with-allowed-web-attack-detected/PLAYBOOK.md) | Exploitation of a public-facing application from an address AWS lists as malicious, served to t | T1190 | High when the reputation label came from |
| [waf.initial-access.sqli-body-detected](playbooks/waf.initial-access.sqli-body-detected/PLAYBOOK.md) | Exploitation of a public-facing application | T1190 | High |
| [waf.stealth.no-logs-from-aws-waf](playbooks/waf.stealth.no-logs-from-aws-waf/PLAYBOOK.md) | Defense impairment | T1685.002 | High |

