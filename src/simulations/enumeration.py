"""
Task definition
1. Enumerate few services - enumerate using the policy simulator
    a. iam list-users
    b. iam list-roles
    c. ec2 describe-instances
    d. lambda list-functions
"""

import boto3
from logger import get_logger

logger = get_logger("enumerations_n_s3_access")

def enumerate_services(action_confirmation_only:bool=False, actions_list:dict=None) -> boto3.client | bool:
    """
    enumerate few services to check if they are available
    Return: None; it only checks if specific service call is
    allowed using the leaked credentials
    Required:
    actions_list = {"service_name": ["action1", "action2"]}
    """

    active_clients = {}
    given_actions = {
        "iam": [
        "iam:ListRoles",
        "iam:ListUsers",
        "iam:GetUser",
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        ],
        "ec2": [
        "ec2:DescribeInstances",
        "ec2:DescribeRegions",
        "ec2:RunInstances",
        "ec2:TerminateInstances",
        ],
        "s3": [
        "s3:ListBuckets",
        "s3:GetObject",
        "s3:PutObject",
        "s3:ListAllMyBuckets",
        ],
        "lambda": [
        "lambda:ListFunctions",
        "lambda:InvokeFunction",
        "lambda:CreateFunction",
        ],
        "rds": [
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters"
        ],
        "kms": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:CreateKey",
        ]
    }

    # enumerate services
    # iam-list-users
    try:
        iam_client = boto3.client("iam")
        sts = boto3.client("sts")

        user_data = sts.get_caller_identity()
        user_arn = user_data.get("Arn")

        given_actions = actions_list if actions_list else given_actions
        for _, actions in given_actions.items():
            actions_decisions = iam_client.simulate_principal_policy(
                PolicySourceArn=user_arn,
                ActionNames=actions,
                ResourceArns=["*"]
            )

            for each_action in actions_decisions.get("EvaluationResults", ()):
                service_name = each_action.get("EvalActionName").split(':', 1)[0]
                if each_action.get("EvalDecision").lower() == "implicitdeny":
                    logger.error(f"service {service_name} is not working")
                    continue
                if not action_confirmation_only:
                    if not active_clients.get(service_name):
                        active_clients[service_name] = boto3.client(service_name, region_name="ap-south-1")
                logger.info(f"service {service_name} is working")
            logger.info("---------")
        
        # check if any of the above enumeration worked or not, if yes return True or False
        if active_clients:
            logger.info(f"active clients: {active_clients.keys()}")
            return active_clients
        return False
    except Exception as err:
        logger.error(err.__str__())