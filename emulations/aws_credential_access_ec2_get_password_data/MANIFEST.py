"""
MANIFEST for the Retrieve EC2 Windows Password Data atomic emulation.

Migrated from Stratus Red Team `aws.credential-access.ec2-get-password-data`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_credential_access_ec2_get_password_data',
 'display_name': 'Retrieve EC2 Windows Password Data',
 'description': 'Simulates an attacker calling ec2:GetPasswordData 30 times against '
                'randomly-generated fake instance IDs. Even though all calls fail with '
                'InvalidInstanceID.NotFound, each generates a CloudTrail event that reveals '
                'credential-hunting behavior.',
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
 'aliases': 'aws.credential-access.ec2-get-password-data',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with EC2 access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Credential Access',
                  'techniques': [{'id': 'T1552.005',
                                  'name': 'Retrieve EC2 Windows Password Data'}]}],
 'mitre_mappings': [{'id': 'T1552.005',
                     'name': 'Retrieve EC2 Windows Password Data',
                     'tactic': 'Credential Access',
                     'platform': 'AWS EC2',
                     'description': 'ec2:GetPasswordData called in rapid succession, especially '
                                    'with nonexistent or unexpected instance IDs'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Retrieve EC2 Windows Password Data',
                 'source': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-get-password-data/',
                 'type': 'REFERENCE',
                 'color': 'cyan'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1552.005',
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
