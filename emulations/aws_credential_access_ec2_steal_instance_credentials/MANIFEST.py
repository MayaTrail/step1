"""
MANIFEST for the Steal EC2 Instance Credentials via IMDS atomic emulation.

Migrated from Stratus Red Team `aws.credential-access.ec2-steal-instance-credentials`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_credential_access_ec2_steal_instance_credentials',
 'display_name': 'Steal EC2 Instance Credentials via IMDS',
 'description': 'Simulates an attacker using SSM to execute a curl command against the EC2 '
                "Instance Metadata Service (IMDS) to steal the attached IAM role's temporary "
                'credentials, then uses those credentials to prove access via STS and EC2 APIs.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['EC2'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Credential Access', 'EC2'],
 'technique_count': 1,
 'severity': 'MEDIUM',
 'aliases': 'aws.credential-access.ec2-steal-instance-credentials',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with EC2 access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Credential Access',
                  'techniques': [{'id': 'T1552.005',
                                  'name': 'Steal EC2 Instance Credentials via IMDS'}]}],
 'mitre_mappings': [{'id': 'T1552.005',
                     'name': 'Steal EC2 Instance Credentials via IMDS',
                     'tactic': 'Credential Access',
                     'platform': 'AWS EC2',
                     'description': 'ssm:SendCommand executing IMDS queries; sts:GetCallerIdentity '
                                    'or ec2:DescribeInstances called with instance-profile '
                                    'credentials from an IP not associated with the instance'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Steal EC2 Instance Credentials via IMDS',
                 'source': 'Stratus Red Team · stratus-red-team.cloud',
                 'type': 'REFERENCE',
                 'color': 'cyan', 'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-steal-instance-credentials/'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1552.005',
                 'source': 'MITRE ATT&CK · mitre.org',
                 'type': 'MITRE',
                 'color': 'purple', 'url': 'https://attack.mitre.org/techniques/T1552/005/'}],
 'phase_count': 1,
 'estimated_duration_minutes': 2,
 'estimated_cost_per_hour_usd': 0.0,
 'default_ttl_hours': 1,
 'total_resources': 0,
 'resources': {'ec2_count': 0, 'instance_types': []},
 'resource_costs': []}
