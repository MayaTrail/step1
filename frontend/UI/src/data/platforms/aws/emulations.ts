import type { Emulation } from '@/types'

export const awsEmulations: Emulation[] = [
  {
    id: 'priv-esc-attach-role-policy',
    name: 'Privilege Escalation \u2014 AttachRolePolicy Abuse',
    origin: 'unknown',
    originLabel: 'TECHNIQUE',
    tags: ['Privilege Escalation', 'IAM Abuse', 'AssumeRole', 'AttachRolePolicy', 'AdministratorAccess'],
    techniqueCount: 4,
    severity: 'CRITICAL',
    aliases: 'IAM Role Policy Attachment \u00b7 Priv-Esc via PassRole',
    attribution: 'Common APT Technique \u2014 APT41, APT29, Lazarus',
    activeSince: 'Persistent Threat Vector',
    targets: 'IAM Users with AssumeRole + AttachRolePolicy permissions',
    incidents: ['SolarWinds IAM Escalation (2020)', 'Capital One Metadata Abuse (2019)', 'APT41 State Government Breach (2021)'],
    attackPath: [
      {
        phase: 1, name: 'Credential Discovery',
        techniques: [
          { id: 'T1087.004', name: 'Cloud Account Discovery' },
          { id: 'T1078.004', name: 'Valid Cloud Accounts' },
        ],
      },
      {
        phase: 2, name: 'Role Assumption',
        techniques: [
          { id: 'T1550.001', name: 'STS AssumeRole' },
          { id: 'T1078', name: 'Valid Accounts' },
        ],
      },
      {
        phase: 3, name: 'Privilege Escalation',
        techniques: [
          { id: 'T1548.005', name: 'Abuse Elevation Control \u2014 AttachRolePolicy' },
          { id: 'T1098', name: 'Account Manipulation \u2014 AdministratorAccess' },
        ],
      },
    ],
    mitreMappings: [
      { id: 'T1078.004', name: 'Valid Cloud Accounts', tactic: 'Initial Access', platform: 'AWS IAM', description: 'Leaked or stolen IAM user credentials with AssumeRole permission' },
      { id: 'T1550.001', name: 'Application Access Token', tactic: 'Lateral Movement', platform: 'AWS STS', description: 'STS AssumeRole to obtain temporary role credentials' },
      { id: 'T1548.005', name: 'Abuse Elevation Control', tactic: 'Privilege Escalation', platform: 'AWS IAM', description: 'Attaching AdministratorAccess policy to an assumable role' },
      { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence', platform: 'AWS IAM', description: 'Escalating role permissions to full admin access' },
    ],
    references: [
      { icon: '\u{1f5c2}\ufe0f', title: 'MITRE ATT&CK \u2014 T1548.005: Abuse Elevation Control Mechanism', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'purple' },
      { icon: '\u{1f52c}', title: 'AWS IAM Privilege Escalation \u2014 Methods and Mitigations', source: 'Rhino Security Labs \u00b7 2023', type: 'RESEARCH', color: 'cyan' },
      { icon: '\u{1f3db}\ufe0f', title: 'CIS AWS Benchmark: IAM Policy Best Practices', source: 'Center for Internet Security \u00b7 2024', type: 'FRAMEWORK', color: 'orange' },
    ],
  },
  {
    id: 'iam-enumeration',
    name: 'Service Enumeration \u2014 IAM Policy Simulator',
    origin: 'unknown',
    originLabel: 'TECHNIQUE',
    tags: ['Discovery', 'Enumeration', 'IAM Simulator', 'Service Recon', 'Permission Mapping'],
    techniqueCount: 6,
    severity: 'MEDIUM',
    aliases: 'AWS Service Enumeration \u00b7 Permission Discovery',
    attribution: 'Common Reconnaissance Technique \u2014 All APT Groups',
    activeSince: 'Persistent Threat Vector',
    targets: 'IAM, EC2, S3, Lambda, RDS, KMS service permissions',
    incidents: ['APT29 Cloud Discovery (2020)', 'APT33 Infrastructure Recon (2023)', 'TeamTNT Credential Mapping (2022)'],
    attackPath: [
      {
        phase: 1, name: 'Credential Acquisition',
        techniques: [
          { id: 'T1078.004', name: 'Valid Cloud Accounts' },
        ],
      },
      {
        phase: 2, name: 'Permission Enumeration',
        techniques: [
          { id: 'T1087.004', name: 'Cloud Account Discovery' },
          { id: 'T1580', name: 'Cloud Infrastructure Discovery' },
          { id: 'T1526', name: 'Cloud Service Discovery' },
        ],
      },
      {
        phase: 3, name: 'Service Mapping',
        techniques: [
          { id: 'T1069.003', name: 'Cloud Groups Discovery' },
          { id: 'T1082', name: 'System Information Discovery' },
        ],
      },
    ],
    mitreMappings: [
      { id: 'T1087.004', name: 'Cloud Account Discovery', tactic: 'Discovery', platform: 'AWS IAM', description: 'Enumerating IAM users, roles, and their permissions via SimulatePrincipalPolicy' },
      { id: 'T1580', name: 'Cloud Infrastructure Discovery', tactic: 'Discovery', platform: 'EC2/Lambda/RDS', description: 'Checking DescribeInstances, ListFunctions, DescribeDBInstances permissions' },
      { id: 'T1526', name: 'Cloud Service Discovery', tactic: 'Discovery', platform: 'Multi-Service', description: 'Mapping available AWS services (S3, KMS, EC2) via policy simulator' },
      { id: 'T1078.004', name: 'Valid Cloud Accounts', tactic: 'Initial Access', platform: 'AWS IAM', description: 'Using leaked credentials to perform enumeration' },
    ],
    references: [
      { icon: '\u{1f5c2}\ufe0f', title: 'MITRE ATT&CK \u2014 T1580: Cloud Infrastructure Discovery', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'purple' },
      { icon: '\u{1f52c}', title: 'Enumerating AWS IAM Permissions: A Practical Guide', source: 'Bishop Fox \u00b7 2023', type: 'RESEARCH', color: 'cyan' },
    ],
  },
  {
    id: 's3-initial-access',
    name: 'S3 Data Exfiltration \u2014 Bucket Access & Ransom',
    origin: 'unknown',
    originLabel: 'TECHNIQUE',
    tags: ['S3 Exfiltration', 'Data Theft', 'Bucket Enumeration', 'Object Deletion', 'Ransom Upload'],
    techniqueCount: 7,
    severity: 'HIGH',
    aliases: 'S3 Bucket Raid \u00b7 Data Exfiltration & Ransom',
    attribution: 'Common Data-Theft Technique \u2014 APT29, Lazarus, FIN7',
    activeSince: 'Persistent Threat Vector',
    targets: 'S3 buckets with misconfigured IAM policies',
    incidents: ['Capital One S3 Data Breach (2019)', 'Imperva S3 Exposure (2019)', 'Twitch Source Code Leak (2021)'],
    attackPath: [
      {
        phase: 1, name: 'Service Enumeration',
        techniques: [
          { id: 'T1580', name: 'Cloud Infrastructure Discovery' },
          { id: 'T1526', name: 'S3 Service Discovery' },
        ],
      },
      {
        phase: 2, name: 'Data Access & Exfiltration',
        techniques: [
          { id: 'T1530', name: 'Data from Cloud Storage (S3)' },
          { id: 'T1119', name: 'Automated Collection \u2014 ListObjects + GetObject' },
        ],
      },
      {
        phase: 3, name: 'Data Destruction & Ransom',
        techniques: [
          { id: 'T1485', name: 'Data Destruction \u2014 DeleteObjects' },
          { id: 'T1491.002', name: 'External Defacement \u2014 Ransom Note Upload' },
        ],
      },
    ],
    mitreMappings: [
      { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection', platform: 'S3', description: 'ListBuckets \u2192 ListObjects \u2192 GetObject to exfiltrate bucket contents' },
      { id: 'T1119', name: 'Automated Collection', tactic: 'Collection', platform: 'S3', description: 'Automated enumeration and download of all S3 objects' },
      { id: 'T1485', name: 'Data Destruction', tactic: 'Impact', platform: 'S3', description: 'Bulk DeleteObjects to destroy bucket data' },
      { id: 'T1491.002', name: 'External Defacement', tactic: 'Impact', platform: 'S3', description: 'Creating new bucket and uploading base64-encoded ransom note' },
      { id: 'T1580', name: 'Cloud Infrastructure Discovery', tactic: 'Discovery', platform: 'S3', description: 'Enumerating S3 buckets and checking bucket policies' },
    ],
    references: [
      { icon: '\u{1f3db}\ufe0f', title: 'CISA Alert: S3 Bucket Misconfiguration and Data Exposure', source: 'CISA \u00b7 2023', type: 'ADVISORY', color: 'danger' },
      { icon: '\u{1f52c}', title: 'S3 Ransomware Attack Patterns in the Wild', source: 'Halcyon \u00b7 2024', type: 'REPORT', color: 'cyan' },
      { icon: '\u{1f5c2}\ufe0f', title: 'MITRE ATT&CK \u2014 T1530: Data from Cloud Storage', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'purple' },
    ],
  },
  {
    id: 's3-kms-ransomware',
    name: 'KMS Ransomware \u2014 S3 Encryption Attack',
    origin: 'unknown',
    originLabel: 'TECHNIQUE',
    tags: ['KMS Ransomware', 'Encryption Attack', 'Key Import', 'Data Hostage', 'Privilege Escalation'],
    techniqueCount: 9,
    severity: 'CRITICAL',
    aliases: 'KMS Ransom \u00b7 Cloud-Native Ransomware \u00b7 S3 Encryption Takeover',
    attribution: 'Advanced Financial-Motivation \u2014 Lazarus, FIN7, ALPHV',
    activeSince: 'Emerging Threat (2023\u2014Present)',
    targets: 'S3 buckets encrypted via KMS, organizations with weak KMS policies',
    incidents: ['S3 KMS Ransomware Campaign (2023)', 'Cloud Ransomware via Imported Key Material (2024)', 'Lazarus KMS-based Data Hostage (2023)'],
    attackPath: [
      {
        phase: 1, name: 'Enumeration & Privilege Escalation',
        techniques: [
          { id: 'T1580', name: 'Cloud Infrastructure Discovery' },
          { id: 'T1548.005', name: 'AttachRolePolicy Escalation' },
          { id: 'T1550.001', name: 'STS AssumeRole' },
        ],
      },
      {
        phase: 2, name: 'KMS Key Creation',
        techniques: [
          { id: 'T1486', name: 'Create External KMS Key' },
          { id: 'T1588.004', name: 'Import Attacker Key Material' },
        ],
      },
      {
        phase: 3, name: 'Data Encryption',
        techniques: [
          { id: 'T1486', name: 'Re-encrypt S3 Objects with Attacker Key' },
        ],
      },
      {
        phase: 4, name: 'Key Material Destruction',
        techniques: [
          { id: 'T1485', name: 'Delete Imported Key Material' },
          { id: 'T1489', name: 'Service Stop \u2014 Data Made Unrecoverable' },
        ],
      },
    ],
    mitreMappings: [
      { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', platform: 'S3/KMS', description: 'Creating external-origin KMS key, importing attacker key material, re-encrypting all S3 objects' },
      { id: 'T1485', name: 'Data Destruction', tactic: 'Impact', platform: 'KMS', description: 'Deleting imported key material making encrypted data permanently unrecoverable' },
      { id: 'T1548.005', name: 'Abuse Elevation Control', tactic: 'Privilege Escalation', platform: 'AWS IAM', description: 'Escalating to AdministratorAccess via AttachRolePolicy before KMS operations' },
      { id: 'T1580', name: 'Cloud Infrastructure Discovery', tactic: 'Discovery', platform: 'S3/KMS', description: 'Enumerating S3 and KMS permissions via policy simulator' },
      { id: 'T1550.001', name: 'Application Access Token', tactic: 'Lateral Movement', platform: 'AWS STS', description: 'AssumeRole to gain KMS:CreateKey and KMS:ImportKeyMaterial permissions' },
    ],
    references: [
      { icon: '\u{1f3db}\ufe0f', title: 'CISA: Cloud-Native Ransomware via KMS Key Manipulation', source: 'CISA \u00b7 2024', type: 'ADVISORY', color: 'danger' },
      { icon: '\u{1f52c}', title: 'S3 Ransomware: Using KMS to Hold Data Hostage', source: 'Halcyon Research \u00b7 2024', type: 'REPORT', color: 'cyan' },
      { icon: '\u{1f5c2}\ufe0f', title: 'MITRE ATT&CK \u2014 T1486: Data Encrypted for Impact', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'purple' },
      { icon: '\u{1f4dd}', title: 'AWS KMS External Key Material Security Considerations', source: 'AWS Security Blog \u00b7 2024', type: 'RESEARCH', color: 'green' },
    ],
  },
  {
    id: 'eventual-consistency-attack',
    name: 'IAM Eventual Consistency \u2014 Race Condition Exploit',
    origin: 'unknown',
    originLabel: 'TECHNIQUE',
    tags: ['Eventual Consistency', 'Race Condition', 'IAM Propagation', 'Policy Deletion', 'Credential Abuse'],
    techniqueCount: 5,
    severity: 'HIGH',
    aliases: 'IAM Propagation Race \u00b7 Consistency Window Exploit',
    attribution: 'Advanced Technique \u2014 Exploits AWS IAM Propagation Delays',
    activeSince: 'Known since 2020 \u2014 Partially mitigated by AWS',
    targets: 'IAM users with active access keys, role policies during key deletion window',
    incidents: ['AWS IAM Eventual Consistency Research Disclosure (2020)', 'Credential Propagation Window Exploit PoC (2022)'],
    attackPath: [
      {
        phase: 1, name: 'Credential Leak & Session Setup',
        techniques: [
          { id: 'T1078.004', name: 'Valid Cloud Accounts \u2014 Leaked Creds' },
          { id: 'T1528', name: 'Steal Application Access Token' },
        ],
      },
      {
        phase: 2, name: 'Race Condition Exploitation',
        techniques: [
          { id: 'T1078', name: 'Use Deleted Credentials Before Propagation' },
        ],
      },
      {
        phase: 3, name: 'Policy Manipulation in Consistency Window',
        techniques: [
          { id: 'T1098', name: 'List & Delete User Policies' },
          { id: 'T1531', name: 'Account Access Removal \u2014 Detach Role Policies' },
          { id: 'T1485', name: 'Data Destruction \u2014 Delete IAM Role' },
        ],
      },
    ],
    mitreMappings: [
      { id: 'T1078.004', name: 'Valid Cloud Accounts', tactic: 'Initial Access', platform: 'AWS IAM', description: 'Attacker uses leaked credentials to create a boto3 session before key is deleted' },
      { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion', platform: 'AWS IAM', description: 'Deleted access keys remain valid during IAM propagation window (seconds to minutes)' },
      { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence', platform: 'AWS IAM', description: 'Listing and deleting user inline policies within the consistency window' },
      { id: 'T1531', name: 'Account Access Removal', tactic: 'Impact', platform: 'AWS IAM', description: 'Detaching managed policies from roles during propagation delay' },
      { id: 'T1485', name: 'Data Destruction', tactic: 'Impact', platform: 'AWS IAM', description: 'Deleting IAM roles after detaching their policies within the window' },
    ],
    references: [
      { icon: '\u{1f52c}', title: 'Exploiting AWS IAM Eventual Consistency for Privilege Abuse', source: 'Daniel Grzelak / Rhino Security Labs \u00b7 2020', type: 'RESEARCH', color: 'cyan' },
      { icon: '\u{1f5c2}\ufe0f', title: 'MITRE ATT&CK \u2014 T1078: Valid Accounts', source: 'MITRE ATT&CK \u00b7 mitre.org', type: 'MITRE', color: 'purple' },
      { icon: '\u{1f4dd}', title: 'AWS IAM Consistency Model Documentation', source: 'AWS Documentation \u00b7 2024', type: 'DOCUMENTATION', color: 'orange' },
    ],
  },
]
