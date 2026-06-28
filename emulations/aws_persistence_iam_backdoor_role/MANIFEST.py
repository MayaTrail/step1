"""
MANIFEST for the Backdoor IAM Role Trust Policy atomic emulation.

Migrated from Stratus Red Team `aws.persistence.iam-backdoor-role`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_persistence_iam_backdoor_role',
 'display_name': 'Backdoor IAM Role Trust Policy',
 'description': "Simulates an attacker modifying an existing IAM role's trust policy to add an "
                'external account (193672423079) as a trusted principal, enabling them to assume '
                'the role from outside the AWS organization.',
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
 'aliases': 'aws.persistence.iam-backdoor-role',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with IAM access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Persistence',
                  'techniques': [{'id': 'T1098', 'name': 'Backdoor IAM Role Trust Policy'}]}],
 'mitre_mappings': [{'id': 'T1098',
                     'name': 'Backdoor IAM Role Trust Policy',
                     'tactic': 'Persistence',
                     'platform': 'AWS IAM',
                     'description': 'iam:UpdateAssumeRolePolicy with an external account principal '
                                    "added to an existing role's trust policy"}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Backdoor IAM Role Trust Policy',
                 'source': 'Stratus Red Team · stratus-red-team.cloud',
                 'type': 'REFERENCE',
                 'color': 'cyan', 'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.iam-backdoor-role/'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1098',
                 'source': 'MITRE ATT&CK · mitre.org',
                 'type': 'MITRE',
                 'color': 'purple', 'url': 'https://attack.mitre.org/techniques/T1098/'}],
 'phase_count': 1,
 'estimated_duration_minutes': 2,
 'estimated_cost_per_hour_usd': 0.0,
 'default_ttl_hours': 1,
 'total_resources': 0,
 'resources': {'ec2_count': 0, 'instance_types': []},
 'resource_costs': []}
