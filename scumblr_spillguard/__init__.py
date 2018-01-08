import logging

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)