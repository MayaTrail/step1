"""
MANIFEST for the Create an IAM User with an Inline Admin Policy atomic emulation.

Migrated from Stratus Red Team `aws.persistence.iam-create-admin-user`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_persistence_iam_create_admin_user',
 'display_name': 'Create an IAM User with an Inline Admin Policy',
 'description': 'Simulates an attacker creating a backdoor IAM user with AdministratorAccess and '
                'generating access keys. No prerequisites required — the attack creates and then '
                'cleans up its own resources.',
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
 'aliases': 'aws.persistence.iam-create-admin-user',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with IAM access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Persistence',
                  'techniques': [{'id': 'T1136.003',
                                  'name': 'Create an IAM User with an Inline Admin Policy'}]}],
 'mitre_mappings': [{'id': 'T1136.003',
                     'name': 'Create an IAM User with an Inline Admin Policy',
                     'tactic': 'Persistence',
                     'platform': 'AWS IAM',
                     'description': 'iam:CreateUser followed immediately by iam:AttachUserPolicy '
                                    'with AdministratorAccess in CloudTrail'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Create an IAM User with an Inline Admin Policy',
                 'source': 'Stratus Red Team · stratus-red-team.cloud',
                 'type': 'REFERENCE',
                 'color': 'cyan', 'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-create-admin-user/'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1136.003',
                 'source': 'MITRE ATT&CK · mitre.org',
                 'type': 'MITRE',
                 'color': 'purple', 'url': 'https://attack.mitre.org/techniques/T1136/003/'}],
 'phase_count': 1,
 'estimated_duration_minutes': 2,
 'estimated_cost_per_hour_usd': 0.0,
 'default_ttl_hours': 1,
 'total_resources': 0,
 'resources': {'ec2_count': 0, 'instance_types': []},
 'resource_costs': []}
