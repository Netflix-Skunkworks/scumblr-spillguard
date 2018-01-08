import logging

logging.basicConfig()
log = logging.getLogger()
log.setLevel(logging.DEBUG)

logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
