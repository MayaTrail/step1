import boto3
from botocore.exceptions import ClientError

def delete_login_profile(username: str) -> None:
    iam = boto3.client("iam")
    try:
        iam.delete_login_profile(UserName=username)
        print(f"Deleted login profile for: {username}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            print(f"No login profile found for: {username}")
        else:
            raise

if __name__ == "__main__":
    delete_login_profile("mayatrail-user")
