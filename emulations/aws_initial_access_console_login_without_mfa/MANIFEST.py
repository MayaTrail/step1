"""
MANIFEST for the Console Login Without MFA atomic emulation.

Migrated from Stratus Red Team `aws.initial-access.console-login-without-mfa`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_initial_access_console_login_without_mfa',
 'display_name': 'Console Login Without MFA',
 'description': 'Simulates an attacker logging into the AWS console using IAM user credentials '
                'without MFA, generating a CloudTrail ConsoleLogin event with MFAUsed=No — a '
                'high-signal indicator for accounts that should enforce MFA.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['IAM'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Initial Access', 'IAM'],
 'technique_count': 1,
 'severity': 'MEDIUM',
 'aliases': 'aws.initial-access.console-login-without-mfa',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with IAM access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Initial Access',
                  'techniques': [{'id': 'T1078.004', 'name': 'Console Login Without MFA'}]}],
 'mitre_mappings': [{'id': 'T1078.004',
                     'name': 'Console Login Without MFA',
                     'tactic': 'Initial Access',
                     'platform': 'AWS IAM',
                     'description': 'CloudTrail ConsoleLogin event with '
                                    'additionalEventData.MFAUsed=No for users that should have MFA '
                                    'enforced'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Console Login Without MFA',
                 'source': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.initial-access.console-login-without-mfa/',
                 'type': 'REFERENCE',
                 'color': 'cyan'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1078.004',
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
