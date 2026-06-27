"""
MANIFEST for the Create IAM User with Console Access atomic emulation.

Migrated from Stratus Red Team `aws.persistence.iam-create-user-login-profile`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_persistence_iam_create_user_login_profile',
 'display_name': 'Create IAM User with Console Access',
 'description': 'Simulates an attacker creating a new IAM user with a console login profile '
                '(password), enabling persistent console access as a new identity that may evade '
                'user-based alerting.',
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
 'aliases': 'aws.persistence.iam-create-user-login-profile',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with IAM access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Persistence',
                  'techniques': [{'id': 'T1136.003',
                                  'name': 'Create IAM User with Console Access'}]}],
 'mitre_mappings': [{'id': 'T1136.003',
                     'name': 'Create IAM User with Console Access',
                     'tactic': 'Persistence',
                     'platform': 'AWS IAM',
                     'description': 'iam:CreateUser followed by iam:CreateLoginProfile — new '
                                    'console-enabled user created outside normal IAM provisioning '
                                    'pipeline'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Create IAM User with Console Access',
                 'source': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-create-user-login-profile/',
                 'type': 'REFERENCE',
                 'color': 'cyan'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1136.003',
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
