"""
MANIFEST for the Create IAM Backdoor Role with Admin Access atomic emulation.

Migrated from Stratus Red Team `aws.persistence.iam-create-backdoor-role`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_persistence_iam_create_backdoor_role',
 'display_name': 'Create IAM Backdoor Role with Admin Access',
 'description': 'Simulates an attacker creating a new IAM role trusted by an external account '
                '(193672423079) and attaching AdministratorAccess, establishing persistent '
                'admin-level access that survives credential rotation.',
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
 'aliases': 'aws.persistence.iam-create-backdoor-role',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with IAM access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Persistence',
                  'techniques': [{'id': 'T1098',
                                  'name': 'Create IAM Backdoor Role with Admin Access'}]}],
 'mitre_mappings': [{'id': 'T1098',
                     'name': 'Create IAM Backdoor Role with Admin Access',
                     'tactic': 'Persistence',
                     'platform': 'AWS IAM',
                     'description': 'iam:CreateRole with a cross-account trust principal followed '
                                    'by iam:AttachRolePolicy attaching AdministratorAccess or '
                                    'broad managed policies'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Create IAM Backdoor Role with Admin Access',
                 'source': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-create-backdoor-role/',
                 'type': 'REFERENCE',
                 'color': 'cyan'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1098',
                 'source': 'MITRE ATT&CK · mitre.org',
                 'type': 'MITRE',
                 'color': 'purple'}],
 'phase_count': 1,
 'estimated_duration_minutes': 2,
 'estimated_cost_per_hour_usd': 0.0,
 'default_ttl_hours': 1,
 'total_resources': 0,
 'resources': {'ec2_count': 0, 'instance_types': []},
 'resource_costs': []}
