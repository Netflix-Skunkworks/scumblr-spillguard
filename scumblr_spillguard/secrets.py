import os
import boto3


def get_secret(name):
    """Retrieves secret from KMS using the name env variable."""
    kms = boto3.session.Session().client("kms")
    return kms.decrypt(CiphertextBlob=os.environ[name].encode('utf-8'))["Plaintext"]
