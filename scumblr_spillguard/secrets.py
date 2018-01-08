import os
import boto3
from scumblr_spillguard import log


def get_secret(name):
    """Retrieves secret from KMS using the name env variable."""
    log.info('Fetching secret from env var. VAR: {}')
    kms = boto3.session.Session().client("kms")
    return kms.decrypt(CiphertextBlob=os.environ[name].encode('utf-8'))["Plaintext"]
