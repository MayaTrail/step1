"""
MANIFEST for the Attempt to Leave the AWS Organization atomic emulation.

Migrated from Stratus Red Team `aws.defense-evasion.organizations-leave`. The id/name is the
import-safe underscore form; the original id is in `aliases`.
schema_version 3.
"""

MANIFEST = {   'schema_version': 3,
    'name': 'aws_defense_evasion_organizations_leave',
    'display_name': 'Attempt to Leave the AWS Organization',
    'description': 'Simulates an attacker in a member account calling organizations:LeaveOrganization to '
                   "escape the organization's SCPs, organization trails and delegated GuardDuty. The call is "
                   'made for real but the attacker role carries an explicit IAM Deny on it, so AWS always '
                   'refuses it and records the attempt in CloudTrail with errorCode AccessDenied. The '
                   'account can never actually leave.',
    'tier': 'atomic',
    'platform': 'aws',
    'added': '2026-10',
    'services': ['Organizations', 'IAM'],
    'readiness': {'type': 'none'},
    'origin': 'stratus-red-team',
    'origin_label': 'ATOMIC TECHNIQUE',
    'tags': ['Defense Evasion', 'Organizations'],
    'technique_count': 1,
    'severity': 'HIGH',
    'aliases': 'aws.defense-evasion.organizations-leave',
    'attribution': 'Stratus Red Team — atomic technique',
    'active_since': 'Atomic technique (Stratus Red Team)',
    'targets': 'AWS Organizations member accounts where principals could call '
               'organizations:LeaveOrganization',
    'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
    'identities': {   'attacker_role': {   'kind': 'lab_role',
                                           'label': "The lab's attacker role",
                                           'output': 'attacker_role_arn'}},
    'attack_path': [   {   'phase': 1,
                           'name': 'Defense Evasion',
                           'aws_actions': [   'organizations:DescribeOrganization',
                                              'organizations:LeaveOrganization',
                                              'sts:AssumeRole'],
                           'acting_as': {   'connected_role': ['sts:AssumeRole'],
                                            'attacker_role': [   'organizations:DescribeOrganization',
                                                                 'organizations:LeaveOrganization']},
                           'aws_resources': {   'sts:AssumeRole': '{attacker_role_arn}',
                                                'organizations:DescribeOrganization': '*',
                                                'organizations:LeaveOrganization': '*'},
                           'techniques': [{'id': 'T1666', 'name': 'Modify Cloud Resource Hierarchy'}]}],
    'mitre_mappings': [   {   'id': 'T1666',
                              'name': 'Modify Cloud Resource Hierarchy',
                              'tactic': 'Defense Evasion',
                              'platform': 'AWS',
                              'description': 'organizations:LeaveOrganization attempt (deny-guarded; logged '
                                             'as AccessDenied)'}],
    'references': [   {   'icon': '>',
                          'title': 'Stratus Red Team — Attempt to Leave the AWS Organization',
                          'source': 'Stratus Red Team · stratus-red-team.cloud',
                          'type': 'REFERENCE',
                          'color': 'cyan',
                          'url': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.defense-evasion.organizations-leave/'},
                      {   'icon': '#',
                          'title': 'MITRE ATT&CK — T1666',
                          'source': 'MITRE ATT&CK · mitre.org',
                          'type': 'MITRE',
                          'color': 'purple',
                          'url': 'https://attack.mitre.org/techniques/T1666/'}],
    'phase_count': 1,
    'estimated_duration_minutes': 3,
    'estimated_cost_per_hour_usd': 0.0,
    'default_ttl_hours': 1,
    'total_resources': 2,
    'resources': {'ec2_count': 0, 'instance_types': []},
    'resource_costs': []}
