import os
import json
import requests
from retrying import retry

from scumblr_spillguard import log
from scumblr_spillguard.secrets import get_secret
from scumblr_spillguard.exceptions import GeneralFailure


def get_rest_url(url):
    """Breaks the base url of the event and reassembles them into a base rest url."""
    rest = ['1.0', 'api', 'rest']
    parts = url.split('/')[2:]

    for r in rest:
        parts.insert(1, r)

    parts.insert(0, 'https:/')
    return '/'.join(parts)


def reconstruct_contents(lines):
    return '\n'.join([l['text'] for l in lines['lines']])


def get_file_url(url):
    """Formats the file URL into something we can actually fetch."""
    parts = url.split('/')[:-2]
    parts.append('browse')

    sha, path = url.split('/')[-1:][0].split('#')
    parts.append(path)

    url = '/'.join(parts) + '?at={}'.format(sha)
    return url


def request(url):
    """Attempt to make a stash request."""
    user = os.environ['BITBUCKET_USER']
    password = get_secret('ENCRYPTED_BITBUCKET_PASSWORD').decode('utf-8')

    url = get_rest_url(url)

    log.debug('Bitbucket Request. Url: {} User: {}'.format(url, user))
    response = requests.get(url, auth=(user, password))

    if not response.ok:
        raise GeneralFailure('Request to Bitbucket failed. URL: {0}'.format(url))

    log.debug('Bitbucket Response. Status: {0} Data: {1}'.format(
        response.status_code,
        json.dumps(response.json(), indent=2)
    ))

    return response.json()
