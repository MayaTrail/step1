"""
MANIFEST for the Retrieve SSM Parameters from the Parameter Store atomic emulation.

Migrated from Stratus Red Team `aws.credential-access.ssm-retrieve-securestring-parameters`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_credential_access_ssm_retrieve_securestring_parameters',
 'display_name': 'Retrieve SSM Parameters from the Parameter Store',
 'description': 'Simulates an attacker enumerating and decrypting SSM SecureString parameters. '
                'Calls DescribeParameters to enumerate then GetParameters with WithDecryption=true '
                'in batches of 10.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['SSM'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Credential Access', 'SSM'],
 'technique_count': 1,
 'severity': 'MEDIUM',
 'aliases': 'aws.credential-access.ssm-retrieve-securestring-parameters',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with SSM access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Credential Access',
                  'techniques': [{'id': 'T1552.007',
                                  'name': 'Retrieve SSM Parameters from the Parameter Store'}]}],
 'mitre_mappings': [{'id': 'T1552.007',
                     'name': 'Retrieve SSM Parameters from the Parameter Store',
                     'tactic': 'Credential Access',
                     'platform': 'AWS SSM',
                     'description': 'ssm:GetParameters with withDecryption=true for large number '
                                    'of parameters from single principal'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Retrieve SSM Parameters from the Parameter Store',
                 'source': 'Stratus Red Team · stratus-red-team.cloud',
                 'type': 'REFERENCE',
                 'color': 'cyan', 'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ssm-retrieve-securestring-parameters/'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1552.007',
                 'source': 'MITRE ATT&CK · mitre.org',
                 'type': 'MITRE',
                 'color': 'purple', 'url': 'https://attack.mitre.org/techniques/T1552/007/'}],
 'phase_count': 1,
 'estimated_duration_minutes': 2,
 'estimated_cost_per_hour_usd': 0.0,
 'default_ttl_hours': 1,
 'total_resources': 0,
 'resources': {'ec2_count': 0, 'instance_types': []},
 'resource_costs': []}
