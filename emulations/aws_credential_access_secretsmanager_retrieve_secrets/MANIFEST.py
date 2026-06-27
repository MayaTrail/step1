"""
MANIFEST for the Retrieve a High Number of Secrets Manager Secrets atomic emulation.

Migrated from Stratus Red Team `aws.credential-access.secretsmanager-retrieve-secrets`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_credential_access_secretsmanager_retrieve_secrets',
 'display_name': 'Retrieve a High Number of Secrets Manager Secrets',
 'description': 'Simulates an attacker retrieving a high number of Secrets Manager secrets by '
                'first enumerating them via ListSecrets then calling GetSecretValue on each. '
                'Generates high-volume GetSecretValue CloudTrail events from a single principal.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['Secrets Manager'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Credential Access', 'Secrets Manager'],
 'technique_count': 1,
 'severity': 'MEDIUM',
 'aliases': 'aws.credential-access.secretsmanager-retrieve-secrets',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with Secrets Manager access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Credential Access',
                  'techniques': [{'id': 'T1555',
                                  'name': 'Retrieve a High Number of Secrets Manager Secrets'}]}],
 'mitre_mappings': [{'id': 'T1555',
                     'name': 'Retrieve a High Number of Secrets Manager Secrets',
                     'tactic': 'Credential Access',
                     'platform': 'AWS Secrets Manager',
                     'description': 'High volume of secretsmanager:GetSecretValue from single '
                                    'principal in short window'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Retrieve a High Number of Secrets Manager Secrets',
                 'source': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.secretsmanager-retrieve-secrets/',
                 'type': 'REFERENCE',
                 'color': 'cyan'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1555',
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
