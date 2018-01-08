import os
import base64
import boto3
from scumblr_spillguard import log


def get_secret(name):
    """Retrieves secret from KMS using the name env variable."""
    log.info('Fetching secret from env var. VAR: {}'.format(name))
    kms = boto3.session.Session().client("kms")
    return kms.decrypt(CiphertextBlob=base64.b64decode(os.environ[name]))["Plaintext"]
