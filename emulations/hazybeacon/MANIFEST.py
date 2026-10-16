"""MANIFEST for the HazyBeacon (CL-STA-1020) serverless C2 emulation. schema_version 3."""

MANIFEST = {   'schema_version': 3,
    'name': 'hazybeacon',
    'display_name': 'HazyBeacon',
    'description': '10-technique AWS emulation of the HazyBeacon (CL-STA-1020) campaign: a harvested '
                   'long-term IAM key is validated, the account is enumerated, and the actor deploys an '
                   'unauthenticated Lambda Function URL as a covert command-and-control relay behind cover '
                   'tags, beacons to it, and inventories exfiltration targets. The lab key can act only on '
                   'its own relay function, the Function URL is removed in a finally block, and no object '
                   'content leaves the lab bucket.',
    'tier': 'enterprise',
    'platform': 'aws',
    'added': '2026-10',
    'services': ['IAM', 'STS', 'Lambda', 'S3', 'Secrets Manager', 'CloudTrail', 'EC2', 'VPC', 'CloudWatch'],
    'readiness': {'type': 'none'},
    'origin': 'unknown',
    'origin_label': 'APT EMULATION',
    'tags': [   'Serverless C2',
                'Lambda Function URL',
                'Stolen IAM Credentials',
                'Cloud Discovery',
                'Defense Evasion',
                'Espionage'],
    'technique_count': 10,
    'severity': 'HIGH',
    'aliases': 'CL-STA-1020',
    'attribution': 'HazyBeacon / CL-STA-1020 (espionage, Southeast Asian government networks)',
    'active_since': 'Documented by Palo Alto Unit 42 (2025) and Qualys (2026)',
    'targets': 'AWS accounts where a developer workstation leaks a long-term IAM access key with Lambda '
               'deploy rights',
    'incidents': ['HazyBeacon: AWS Lambda Function URL command-and-control abuse (Qualys)'],
    'identities': {   'victim_user': {   'kind': 'lab_user',
                                         'label': "The lab's victim user",
                                         'output': 'victim_iam_user_name'}},
    'attack_path': [   {   'phase': 1,
                           'name': 'Reconnaissance (Documented)',
                           'aws_actions': [],
                           'techniques': [   {   'id': 'T1598.003',
                                                 'name': 'Phishing for Information: Spearphishing Link'},
                                             {   'id': 'T1552.001',
                                                 'name': 'Unsecured Credentials: Credentials In Files'}]},
                       {   'phase': 2,
                           'name': 'Initial Access & Discovery',
                           'aws_actions': [   'iam:GetAccountSummary',
                                              'iam:GetPolicy',
                                              'iam:GetUser',
                                              'iam:GetUserPolicy',
                                              'iam:ListAttachedGroupPolicies',
                                              'iam:ListGroups',
                                              'iam:ListGroupsForUser',
                                              'iam:ListRoles',
                                              'iam:ListUserPolicies',
                                              'iam:ListUsers',
                                              's3:ListAllMyBuckets',
                                              'secretsmanager:DescribeSecret',
                                              'secretsmanager:ListSecrets',
                                              'sts:GetCallerIdentity'],
                           'acting_as': 'victim_user',
                           'aws_resources': {   'iam:GetAccountSummary': '*',
                                                'iam:GetPolicy': '*',
                                                'iam:GetUser': '*',
                                                'iam:GetUserPolicy': '{victim_user_arn}',
                                                'iam:ListAttachedGroupPolicies': '*',
                                                'iam:ListGroups': '*',
                                                'iam:ListGroupsForUser': '{victim_user_arn}',
                                                'iam:ListRoles': '*',
                                                'iam:ListUserPolicies': '{victim_user_arn}',
                                                'iam:ListUsers': '*',
                                                's3:ListAllMyBuckets': '*',
                                                'secretsmanager:DescribeSecret': '{secret_arn}',
                                                'secretsmanager:ListSecrets': '*',
                                                'sts:GetCallerIdentity': '*'},
                           'techniques': [   {'id': 'T1078.004', 'name': 'Valid Accounts: Cloud Accounts'},
                                             {'id': 'T1087.004', 'name': 'Account Discovery: Cloud Account'},
                                             {   'id': 'T1069.003',
                                                 'name': 'Permission Groups Discovery: Cloud Groups'}]},
                       {   'phase': 3,
                           'name': 'Execution & Defense Evasion',
                           'aws_actions': [   'iam:PassRole',
                                              'lambda:AddPermission',
                                              'lambda:CreateFunction',
                                              'lambda:CreateFunctionUrlConfig',
                                              'lambda:GetFunction',
                                              'lambda:TagResource'],
                           'acting_as': 'victim_user',
                           'aws_resources': {   'iam:PassRole': '{lambda_exec_role_arn}',
                                                'lambda:AddPermission': 'arn:aws:lambda:{region}:{account_id}:function:{relay_lambda_function_name}',
                                                'lambda:CreateFunction': 'arn:aws:lambda:{region}:{account_id}:function:{relay_lambda_function_name}',
                                                'lambda:CreateFunctionUrlConfig': 'arn:aws:lambda:{region}:{account_id}:function:{relay_lambda_function_name}',
                                                'lambda:GetFunction': 'arn:aws:lambda:{region}:{account_id}:function:{relay_lambda_function_name}',
                                                'lambda:TagResource': 'arn:aws:lambda:{region}:{account_id}:function:{relay_lambda_function_name}'},
                           'techniques': [   {'id': 'T1648', 'name': 'Serverless Execution'},
                                             {'id': 'T1564', 'name': 'Hide Artifacts'}]},
                       {   'phase': 4,
                           'name': 'Command & Control, Exfiltration & Cleanup',
                           'aws_actions': [   'lambda:DeleteFunction',
                                              'lambda:DeleteFunctionUrlConfig',
                                              'lambda:InvokeFunctionUrl',
                                              'lambda:RemovePermission',
                                              's3:GetObject',
                                              's3:ListBucket'],
                           'acting_as': {   'victim_user': [   'lambda:DeleteFunction',
                                                               'lambda:DeleteFunctionUrlConfig',
                                                               'lambda:RemovePermission',
                                                               's3:GetObject',
                                                               's3:ListBucket'],
                                            'anonymous': ['lambda:InvokeFunctionUrl']},
                           'aws_resources': {   'lambda:DeleteFunction': 'arn:aws:lambda:{region}:{account_id}:function:{relay_lambda_function_name}',
                                                'lambda:DeleteFunctionUrlConfig': 'arn:aws:lambda:{region}:{account_id}:function:{relay_lambda_function_name}',
                                                'lambda:RemovePermission': 'arn:aws:lambda:{region}:{account_id}:function:{relay_lambda_function_name}',
                                                'lambda:InvokeFunctionUrl': 'arn:aws:lambda:{region}:{account_id}:function:{relay_lambda_function_name}',
                                                's3:ListBucket': 'arn:aws:s3:::{exfil_bucket_name}',
                                                's3:GetObject': 'arn:aws:s3:::{exfil_bucket_name}/{tfstate_object_key}'},
                           'techniques': [   {'id': 'T1102', 'name': 'Web Service'},
                                             {'id': 'T1090', 'name': 'Proxy'},
                                             {'id': 'T1041', 'name': 'Exfiltration Over C2 Channel'}]}],
    'mitre_mappings': [   {   'id': 'T1598.003',
                              'name': 'Phishing for Information: Spearphishing Link',
                              'tactic': 'Reconnaissance',
                              'platform': 'AWS',
                              'description': 'HazyBeacon delivers a spearphishing link to the target '
                                             'developer, leading to HazyBeacon backdoor installation on the '
                                             'developer workstation. The backdoor subsequently reads '
                                             '~/.aws/credentials. Documented only — emulation begins with '
                                             'credentials pre-planted by EC2 UserData.'},
                          {   'id': 'T1552.001',
                              'name': 'Unsecured Credentials: Credentials In Files',
                              'tactic': 'Credential Access',
                              'platform': 'AWS',
                              'description': 'HazyBeacon backdoor reads AWS credentials from '
                                             '~/.aws/credentials and ~/projects/infra-prod/terraform.tfstate '
                                             'on the compromised developer workstation. Simulated via EC2 '
                                             'UserData — attack.py receives the harvested credentials as '
                                             'Pulumi stack outputs and does NOT interact with the EC2 '
                                             'filesystem.'},
                          {   'id': 'T1078.004',
                              'name': 'Valid Accounts: Cloud Accounts',
                              'tactic': 'Initial Access',
                              'platform': 'AWS',
                              'description': 'Use the harvested static IAM access key to authenticate to AWS '
                                             'and validate credential validity. GetCallerIdentity confirms '
                                             'the account ID and user ARN; GetUser retrieves the IAM '
                                             'identity metadata. These are the first control-plane API calls '
                                             'made with stolen credentials, establishing the session use'},
                          {   'id': 'T1087.004',
                              'name': 'Account Discovery: Cloud Account',
                              'tactic': 'Discovery',
                              'platform': 'AWS',
                              'description': 'Enumerate IAM identities, account summary, S3 buckets, and '
                                             'SecretsManager secrets to map the victim AWS environment. '
                                             'Discovers hazybeacon-decoy-admin-user (honey IAM user), '
                                             'hazybeacon-exfil-bucket (target S3 bucket), and '
                                             'hazybeacon-secrets (fake database credentials). DescribeSecret '
                                             'confirms high-va'},
                          {   'id': 'T1069.003',
                              'name': 'Permission Groups Discovery: Cloud Groups',
                              'tactic': 'Discovery',
                              'platform': 'AWS',
                              'description': 'Enumerate IAM groups and policy attachments to map permission '
                                             'boundaries and identify escalation paths. HazyBeacon reads '
                                             'group memberships and inline/managed policy documents to '
                                             'confirm the compromised identity has Lambda deployment rights '
                                             'before proceeding to T1648.'},
                          {   'id': 'T1648',
                              'name': 'Serverless Execution',
                              'tactic': 'Execution',
                              'platform': 'AWS',
                              'description': 'Deploy a Lambda function named BackupHandler with a benign '
                                             'description to serve as the HazyBeacon C2 relay. Function code '
                                             'is a simulated echo handler packaged as an in-memory ZIP (no '
                                             'disk write). Lambda Function URL is created with AuthType:NONE '
                                             'to expose a public HTTPS endpoint. PassRole is exercis'},
                          {   'id': 'T1564',
                              'name': 'Hide Artifacts',
                              'tactic': 'Defense Evasion',
                              'platform': 'AWS',
                              'description': 'Apply innocuous organizational-style resource tags to the '
                                             'BackupHandler Lambda function to help it blend into legitimate '
                                             'infrastructure during visual review. HazyBeacon uses common '
                                             'tag schemas (Environment, Team, ManagedBy) to reduce the '
                                             'likelihood of the function being flagged as anomalous in cost'},
                          {   'id': 'T1102',
                              'name': 'Web Service',
                              'tactic': 'Command and Control',
                              'platform': 'AWS',
                              'description': 'Simulate HazyBeacon beaconing to the deployed BackupHandler '
                                             'Lambda Function URL to establish a C2 channel over HTTPS. Per '
                                             'operational constraint: only synthetic beacon metadata is '
                                             'transmitted, the Lambda echo returns a static beacon_ack '
                                             'response, and no real C2 payload is relayed. Round-trip '
                                             'latency'},
                          {   'id': 'T1090',
                              'name': 'Proxy',
                              'tactic': 'Command and Control',
                              'platform': 'AWS',
                              'description': 'Documented: HazyBeacon uses the deployed BackupHandler Lambda '
                                             'function as a proxy forwarding C2 traffic from the compromised '
                                             'host to attacker-controlled backend infrastructure, obscuring '
                                             'true C2 origins behind a legitimate AWS domain. Not '
                                             'implemented in attack.py — the static echo handler deployed i'},
                          {   'id': 'T1041',
                              'name': 'Exfiltration Over C2 Channel',
                              'tactic': 'Exfiltration',
                              'platform': 'AWS',
                              'description': 'Simulate exfiltration of sensitive data from '
                                             'hazybeacon-exfil-bucket via the BackupHandler Lambda C2 relay. '
                                             'Attack script performs read-only S3 enumeration '
                                             '(list_objects_v2, head_object on terraform.tfstate bait) to '
                                             'identify exfiltration targets, logs what would be transmitted, '
                                             'then sends a mock POS'}],
    'references': [   {   'icon': '>',
                          'title': 'HazyBeacon: AWS Lambda Function URL command-and-control abuse',
                          'source': 'Qualys Blog · blog.qualys.com',
                          'type': 'REPORT',
                          'color': 'cyan',
                          'url': 'https://blog.qualys.com/qualys-insights/2026/06/02/hazybeacon-aws-lambda-function-url-command-control-abuse'},
                      {   'icon': '#',
                          'title': 'MITRE ATT&CK - T1648 Serverless Execution',
                          'source': 'MITRE ATT&CK · mitre.org',
                          'type': 'MITRE',
                          'color': 'purple',
                          'url': 'https://attack.mitre.org/techniques/T1648/'},
                      {   'icon': '#',
                          'title': 'MITRE ATT&CK - T1102 Web Service',
                          'source': 'MITRE ATT&CK · mitre.org',
                          'type': 'MITRE',
                          'color': 'purple',
                          'url': 'https://attack.mitre.org/techniques/T1102/'},
                      {   'icon': '>',
                          'title': 'AWS Lambda - Control access to function URLs',
                          'source': 'AWS Documentation · docs.aws.amazon.com',
                          'type': 'REFERENCE',
                          'color': 'cyan',
                          'url': 'https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html'}],
    'phase_count': 4,
    'default_ttl_hours': 2,
    'estimated_duration_minutes': 20,
    'estimated_cost_per_hour_usd': 0.02,
    'total_resources': 19,
    'resources': {   'ec2_count': 1,
                     'instance_types': ['t3.micro'],
                     'uses_lambda': True,
                     'uses_secrets_manager': True,
                     'uses_cloudtrail': True,
                     'uses_guardduty': False},
    'resource_costs': []}
