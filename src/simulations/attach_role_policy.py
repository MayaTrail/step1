# Task: Add AdministratorAccess Policy to a role arn"
# Let's suppose mayatrail-test is a sus user

import os
import boto3

def get_role_creds(role_arn: str):
    """
    get role credentials
    """
    sts_client = boto3.client("sts")
    
    # debug: check which user is making the assume role call
    caller_identity = sts_client.get_caller_identity()
    print(f"Assuming role as user: {caller_identity['Arn']}")
    
    try:
        assume_role_obj = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="mayatrail-test"
        )

        role_creds = {
            "AWS_ACCESS_KEY_ID": assume_role_obj["Credentials"]["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": assume_role_obj["Credentials"]["SecretAccessKey"],
            "AWS_SESSION_TOKEN": assume_role_obj["Credentials"]["SessionToken"]
        }

        return role_creds
    except Exception as err:
        raise Exception(err.__str__())

def attach_administrator_policy(role_name: str):
    """attach AdministratorAccess to a role"""

    iam_client = boto3.client("iam") # this is a global servie, no region is required
    try:
        resp = iam_client.attach_role_policy(
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            RoleName=role_name
        )
        return resp
    except Exception as err:
        raise Exception(err.__str__())