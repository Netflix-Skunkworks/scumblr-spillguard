import hmac
import hashlib
import requests
from retrying import retry

from scumblr_spillguard import log
from scumblr_spillguard.utils import validate_ip
from scumblr_spillguard.secrets import get_secret
from scumblr_spillguard.exceptions import GeneralFailure, ThrottledError, AuthorizationError


GITHUB_CIDR_WHITELIST = ['192.30.252.0/22', '185.199.108.0/22']


def github_thottled(exception):
    """We should retry if we think we can successfully complete the request within the lambda timeout."""
    log.exception(exception)
    return isinstance(exception, ThrottledError)


def validate(event):
    """Ensure the incoming event is a github event."""
    authorize(event['body'], event['headers'], event['requestContext']['identity']['sourceIp'])
    if event.get('resource') == '/github':
        if event.get('requestContext'):
            if event['requestContext'].get('identity'):
                if event['requestContext']['identity'].get('userAgent'):
                    if event['requestContext']['identity']['userAgent'].startswith('GitHub-Hookshot'):
                        return

    raise GeneralFailure('Invalid event. Event: {}'.format(event))


def authorize(body, headers, source_ip):
    """Ensures that we have a valid github webhook."""
    validate_ip(source_ip, GITHUB_CIDR_WHITELIST)

    sha_name, signature = headers['X-Hub-Signature'].split('=')
    if sha_name != 'sha1':
        raise AuthorizationError('Signature algorithm is not SHA1')

    message_hmac = hmac.new(
        get_secret('ENCRYPTED_WEBHOOK_SECRET'),
        body.encode('utf-8'),
        hashlib.sha1
    )

    if not hmac.compare_digest(signature, message_hmac.hexdigest()):
        raise AuthorizationError('Computed HMAC {} does not match signature {}'.format(message_hmac.hexdigest(), signature))

    log.debug('Computed HMAC {} matches signature {}'.format(message_hmac.hexdigest(), signature))


@retry(retry_on_exception=github_thottled, wait_random_min=1000, wait_random_max=10000)
def request(url):
    """Attempt to make a Github request."""
    params = {'access_token': get_secret('ENCRYPTED_GITHUB_TOKEN')}

    log.info('Checking url {}'.format(url))

    response = requests.get(url, params=params)

    if not response.ok:
        raise GeneralFailure('Request to Github failed. URL: {0}'.format(url))

    log.info('Github response: {}'.format(response.json()))

    if response.headers['X-RateLimit-Remaining'] == 0:
        log.info('Throttled by Github. X-RateLimit-Limit: {0}'.format(
            response.headers['X-RateLimit-Limit']))
        raise ThrottledError()

    return response.json()
