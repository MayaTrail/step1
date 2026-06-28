"""
MANIFEST for the Backdoor IAM User with Additional Access Key atomic emulation.

Migrated from Stratus Red Team `aws.persistence.iam-backdoor-user`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_persistence_iam_backdoor_user',
 'display_name': 'Backdoor IAM User with Additional Access Key',
 'description': 'Simulates an attacker creating a second access key for an existing IAM user, '
                'giving them persistent programmatic access even if the original key is rotated. A '
                'single iam:CreateAccessKey call is the only CloudTrail evidence.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['IAM'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Persistence', 'IAM'],
 'technique_count': 1,
 'severity': 'MEDIUM',
 'aliases': 'aws.persistence.iam-backdoor-user',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with IAM access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Persistence',
                  'techniques': [{'id': 'T1098.001',
                                  'name': 'Backdoor IAM User with Additional Access Key'}]}],
 'mitre_mappings': [{'id': 'T1098.001',
                     'name': 'Backdoor IAM User with Additional Access Key',
                     'tactic': 'Persistence',
                     'platform': 'AWS IAM',
                     'description': 'iam:CreateAccessKey on an existing user where the requesting '
                                    'principal is NOT the user themselves — indicates an external '
                                    'actor creating credentials'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Backdoor IAM User with Additional Access Key',
                 'source': 'Stratus Red Team · stratus-red-team.cloud',
                 'type': 'REFERENCE',
                 'color': 'cyan', 'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-backdoor-user/'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1098.001',
                 'source': 'MITRE ATT&CK · mitre.org',
                 'type': 'MITRE',
                 'color': 'purple', 'url': 'https://attack.mitre.org/techniques/T1098/001/'}],
 'phase_count': 1,
 'estimated_duration_minutes': 2,
 'estimated_cost_per_hour_usd': 0.0,
 'default_ttl_hours': 1,
 'total_resources': 0,
 'resources': {'ec2_count': 0, 'instance_types': []},
 'resource_costs': []}
