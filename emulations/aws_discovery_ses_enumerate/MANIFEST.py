"""
MANIFEST for the Enumerate SES for Phishing Capability atomic emulation.

Migrated from Stratus Red Team `aws.discovery.ses-enumerate`. The id/name is the import-safe
underscore form; the original id is in `aliases`. schema_version 3 — see
emulations/_kb/AUTHORING.md. Fields marked TODO above should be refined.
"""

MANIFEST = {'schema_version': 3,
 'name': 'aws_discovery_ses_enumerate',
 'display_name': 'Enumerate SES for Phishing Capability',
 'description': 'Simulates an attacker probing AWS SES to assess phishing capability: checks '
                'sending limits, verified identities, and account sending status. Multiple read '
                "APIs called in rapid succession reveal the attacker's intent to abuse email "
                'infrastructure.',
 'tier': 'atomic',
 'platform': 'aws',
 'added': '2026-06',
 'services': ['SES'],
 'readiness': {'type': 'none'},
 'origin': 'stratus-red-team',
 'origin_label': 'ATOMIC TECHNIQUE',
 'tags': ['Discovery', 'SES'],
 'technique_count': 1,
 'severity': 'LOW',
 'aliases': 'aws.discovery.ses-enumerate',
 'attribution': 'Stratus Red Team — atomic technique',
 'active_since': 'Atomic technique (Stratus Red Team)',
 'targets': 'AWS accounts with SES access',
 'incidents': ['Stratus Red Team — AWS attack technique catalogue'],
 'attack_path': [{'phase': 1,
                  'name': 'Discovery',
                  'techniques': [{'id': 'T1087',
                                  'name': 'Enumerate SES for Phishing Capability'}]}],
 'mitre_mappings': [{'id': 'T1087',
                     'name': 'Enumerate SES for Phishing Capability',
                     'tactic': 'Discovery',
                     'platform': 'AWS SES',
                     'description': 'Multiple SES read APIs (ses:GetAccountSendingEnabled, '
                                    'ses:GetSendQuota, ses:ListIdentities, '
                                    'ses:GetIdentityVerificationAttributes) called in rapid '
                                    'succession from unexpected principals'}],
 'references': [{'icon': '>',
                 'title': 'Stratus Red Team — Enumerate SES for Phishing Capability',
                 'source': 'https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ses-enumerate/',
                 'type': 'REFERENCE',
                 'color': 'cyan'},
                {'icon': '#',
                 'title': 'MITRE ATT&CK — T1087',
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
