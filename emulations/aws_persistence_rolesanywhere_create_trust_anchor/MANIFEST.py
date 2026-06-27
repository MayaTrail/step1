"""
MANIFEST for the Create IAM Roles Anywhere Trust Anchor atomic emulation.

Migrated from Stratus Red Team `aws.persistence.rolesanywhere-create-trust-anchor`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_persistence_rolesanywhere_create_trust_anchor',
 'display_name': 'Create IAM Roles Anywhere Trust Anchor',
 'description': 'Simulates an attacker creating an IAM Roles Anywhere trust anchor using a '
                'self-signed certificate, enabling external workloads to assume IAM roles using '
                'X.509 certificates without long-term AWS credentials.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['IAM Roles Anywhere'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Persistence', 'IAM Roles Anywhere'],
 'technique_count': 1,
 'severity': 'MEDIUM',
 'aliases': 'aws.persistence.rolesanywhere-create-trust-anchor',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with IAM Roles Anywhere access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Persistence',
                  'techniques': [{'id': 'T1550.001',
                                  'name': 'Create IAM Roles Anywhere Trust Anchor'}]}],
 'mitre_mappings': [{'id': 'T1550.001',
                     'name': 'Create IAM Roles Anywhere Trust Anchor',
                     'tactic': 'Persistence',
                     'platform': 'AWS IAM Roles Anywhere',
                     'description': 'rolesanywhere:CreateTrustAnchor — rare API call almost never '
                                    'made outside initial IAM Roles Anywhere setup; warrants '
                                    'immediate investigation'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Create IAM Roles Anywhere Trust Anchor',
                 'source': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.persistence.rolesanywhere-create-trust-anchor/',
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
