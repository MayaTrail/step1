"""
MANIFEST for the Backdoor IAM User Console Login via UpdateLoginProfile atomic emulation.

Migrated from Stratus Red Team `aws.privilege-escalation.iam-update-user-login-profile`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_privilege_escalation_iam_update_user_login_profile',
 'display_name': 'Backdoor IAM User Console Login via UpdateLoginProfile',
 'description': 'Simulates an attacker with iam:UpdateLoginProfile permission changing a '
                "legitimate IAM user's console password to one they control, enabling console "
                'login as that user. High-signal single API call with no prerequisites beyond the '
                'target user existing.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['IAM'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Privilege Escalation', 'IAM'],
 'technique_count': 1,
 'severity': 'HIGH',
 'aliases': 'aws.privilege-escalation.iam-update-user-login-profile',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with IAM access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Privilege Escalation',
                  'techniques': [{'id': 'T1098.001',
                                  'name': 'Backdoor IAM User Console Login via '
                                          'UpdateLoginProfile'}]}],
 'mitre_mappings': [{'id': 'T1098.001',
                     'name': 'Backdoor IAM User Console Login via UpdateLoginProfile',
                     'tactic': 'Privilege Escalation',
                     'platform': 'AWS IAM',
                     'description': 'iam:UpdateLoginProfile in CloudTrail where the caller is not '
                                    'an expected administrator or password-reset automation'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Backdoor IAM User Console Login via '
                          'UpdateLoginProfile',
                 'source': 'Stratus Red Team · stratus-red-team.cloud',
                 'type': 'REFERENCE',
                 'color': 'cyan', 'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.privilege-escalation.iam-update-user-login-profile/'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1098.001',
                 'source': 'MITRE ATT&CK · mitre.org',
                 'type': 'MITRE',
                 'color': 'purple', 'url': 'https://attack.mitre.org/techniques/T1098/001/'}],
 'phase_count': 1,
 'estimated_duration_minutes': 2,
 'estimated_cost_per_hour_usd': 0.0,
 'default_ttl_hours': 1,
 'total_resources': 0,
 'resources': {'ec2_count': 0, 'instance_types': []},
 'resource_costs': []}
