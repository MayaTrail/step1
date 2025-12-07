# import pulumi and pulumi_aws
import os
import json
import pulumi
import pulumi_aws as aws
from simulations import attach_role_policy

class MayaTrailInfra:

    def __init__(self):
        self.username = "mayatrail-user"
        self.rolename = "mayatrail-role"
        self.account_id = "104266513052"
        self.bucket_name = "mayatrail-step1-bucket"
        self.region = "ap-south-1"
        self.user = None
        self.role = None


    def create_dummies(self, type: str) -> aws.iam.User | aws.iam.Role | ValueError:
        """
        create IAM user and role with no policies attached
        """
        if type.lower() == "user":
            # create an aws resource (iam user)
            user_object = aws.iam.User(self.username,
                name=self.username,
                path="/",
                tags={
                    "test-key": "test-value",
                }
            )
            # create dummy access key
            self._create_user_access_key(user_object)
            self.user = user_object
        elif type.lower() == "role":
            # assume role policy document assings to the trust relationship of a role
            # keys naming convention should be strict as per AWS trust relationship document
            role_object = aws.iam.Role(self.rolename,
                assume_role_policy=json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": f"arn:aws:iam::{self.account_id}:user/{self.username}"
                                },
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    }
                ),
                tags = {"Environment": "dev"},
                description = "this role has been created using pulumi",
                max_session_duration = 3600 # session will only be up for 5 min.
            )   
            self.role = role_object
        else:
            raise ValueError("Invalid type\nValid types are 'user' and 'role'")

    def attach_policies(self, type: str, policy_statements: list[dict]) -> aws.iam.UserPolicyAttachment | aws.iam.RolePolicyAttachment | ValueError:
        """
        attach policies to the user or role
        """
        if policy_statements is None:
            raise ValueError("Policy statement is required") 

        # get_policy_document is a data source function, it doesn't create an resource on AWS
        policy_document = aws.iam.get_policy_document_output(
            statements=policy_statements
        )
        # create policy on aws and get arn
        policy_object = aws.iam.Policy("mayatrail-role-policy" if type=="role" else "mayatrail-user-policy",
            policy=policy_document.json
        )

        if type.lower() == "user":
            # attach policy to user
            aws.iam.UserPolicyAttachment("mayatrail-test-user-policy-attachment",
                policy_arn=policy_object.arn,
                user=self.user.name
            )
        elif type.lower() == "role":
            # attach policy to role
            aws.iam.RolePolicyAttachment("mayatrail-test-role-policy-attachment",
                policy_arn=policy_object.arn,
                role=self.role.name
            )
        else:
            ValueError("Invalid type\nValid types are 'user' and 'role'")

    def _create_user_access_key(self, user_obj: aws.iam.User):
        """
        initialize user with a access key
        """
	
        access_key_obj = aws.iam.AccessKey("mayatrail-dummy-access-key",
            user=user_obj,
            status='Active'
        )

        self._access_key_id = access_key_obj.id
        self._secret_access_key = access_key_obj.secret

    def create_s3_bucket(self, bucket_name:str=None):
        """
        create a s3 bucket and upload one bucket object
        """

        # create general purpose bucket with given name
        bucket = aws.s3.Bucket("mayatrail-s3-bucket",
            bucket=bucket_name if bucket_name else self.bucket_name,
            region=self.region
        )

        # put few objects in the above created bucket
        bucketObj = aws.s3.BucketObjectv2("mayatrail-s3-bucket-object",
            bucket = bucket.id,
            key="dummy-text-file1",
            content="this is a sample text file! Uploaded by pulumi"
        )

        object_url = pulumi.Output.concat("https://", bucket.bucket_regional_domain_name, "/", bucketObj.key)
        pulumi.export("object_url", object_url)


def setup():
    mayatrail = MayaTrailInfra()

    # create dummy user and role
    mayatrail.create_dummies(type="user")
    mayatrail.create_dummies(type="role")

    # attach policies to user and role
    # user - IAM full access
    # role - AttachRolePolicy

    # keys naming convention here shouldn't be strict and can be used in lowercase.
    mayatrail.attach_policies(type="user", policy_statements=[
        {
            "effect": "Allow",
            "actions": ["iam:*"],
            "resources": ["*"]
        },
        {
            "effect": "Allow",
            "actions": ["sts:AssumeRole"],
            "resources": mayatrail.role.arn
        }
    ])

    mayatrail.attach_policies(type="role", policy_statements=[
        {
            "effect": "Allow",
            "actions": ["iam:AttachRolePolicy"],
            "resources": ["*"]
        }
    ])

    mayatrail.create_s3_bucket()

    pulumi.export("username", mayatrail._access_key_id)
    pulumi.export("role_arn", mayatrail.role.arn)

    # output.apply() to unwrap pulumi output values | normal os.environ won't work
    # access_key_obj contain async values not normal plain strings
    #role_creds = pulumi.Output.all(
    #    mayatrail._access_key_id, 
    #    mayatrail._secret_access_key, 
    #    mayatrail.role.arn,
    #    mayatrail.role.name
    #).apply(mayatrail.setup_and_run_simulation)
    #pulumi.export("role_credentials", role_creds)

setup()