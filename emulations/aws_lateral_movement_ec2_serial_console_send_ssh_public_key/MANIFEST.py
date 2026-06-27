"""
MANIFEST for the Usage of EC2 Serial Console to Push an SSH Public Key atomic emulation.

Migrated from Stratus Red Team `aws.lateral-movement.ec2-serial-console-send-ssh-public-key`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_lateral_movement_ec2_serial_console_send_ssh_public_key',
 'display_name': 'Usage of EC2 Serial Console to Push an SSH Public Key',
 'description': 'Simulates an attacker pushing their SSH public key to an EC2 instance via the '
                'serial console API, which bypasses security groups and network ACLs — providing '
                'access even when port 22 is blocked.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['EC2'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Lateral Movement', 'EC2'],
 'technique_count': 1,
 'severity': 'MEDIUM',
 'aliases': 'aws.lateral-movement.ec2-serial-console-send-ssh-public-key',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with EC2 access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Lateral Movement',
                  'techniques': [{'id': 'T1021.004',
                                  'name': 'Usage of EC2 Serial Console to Push an SSH Public '
                                          'Key'}]}],
 'mitre_mappings': [{'id': 'T1021.004',
                     'name': 'Usage of EC2 Serial Console to Push an SSH Public Key',
                     'tactic': 'Lateral Movement',
                     'platform': 'AWS EC2',
                     'description': 'CloudTrail ec2-instance-connect:SendSerialConsoleSSHPublicKey '
                                    '— a niche API almost never called in normal operations'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Usage of EC2 Serial Console to Push an SSH Public '
                          'Key',
                 'source': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.lateral-movement.ec2-serial-console-send-ssh-public-key/',
                 'type': 'REFERENCE',
                 'color': 'cyan'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1021.004',
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
