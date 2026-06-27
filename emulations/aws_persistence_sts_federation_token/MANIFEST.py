"""
MANIFEST for the Backdoor IAM User with Federated Token atomic emulation.

Migrated from Stratus Red Team `aws.persistence.sts-federation-token`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_persistence_sts_federation_token',
 'display_name': 'Backdoor IAM User with Federated Token',
 'description': 'Simulates an attacker using sts:GetFederationToken to mint long-lived federated '
                'credentials (up to 36 hours) with an attacker-controlled inline policy, providing '
                'persistent access that survives access key rotation.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['STS'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Persistence', 'STS'],
 'technique_count': 1,
 'severity': 'MEDIUM',
 'aliases': 'aws.persistence.sts-federation-token',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with STS access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Persistence',
                  'techniques': [{'id': 'T1550.001',
                                  'name': 'Backdoor IAM User with Federated Token'}]}],
 'mitre_mappings': [{'id': 'T1550.001',
                     'name': 'Backdoor IAM User with Federated Token',
                     'tactic': 'Persistence',
                     'platform': 'AWS STS',
                     'description': 'sts:GetFederationToken called with a permissive inline policy '
                                    'or from an unexpected principal; federated sessions appear in '
                                    'CloudTrail with token source info'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Backdoor IAM User with Federated Token',
                 'source': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.sts-federation-token/',
                 'type': 'REFERENCE',
                 'color': 'cyan'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1550.001',
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
