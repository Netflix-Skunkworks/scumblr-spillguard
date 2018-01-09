import os
import json
import requests

from scumblr_spillguard import log
from scumblr_spillguard.utils import mktempfile
from scumblr_spillguard.secrets import get_secret
from scumblr_spillguard.exceptions import GeneralFailure

CWD = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

SCUMBLR_URL = os.environ["SCUMBLR_URL"]
SCUMBLR_CLIENT_PATH = os.path.join(CWD, os.environ.get("SCUMBLR_CLIENT_PATH", "SCUMBLR_CLIENT.cert"))


def get_config(name):
    """Return the current scumblr task configuration."""
    return request(
        '/tasks/search?q[task_type_eq]=ScumblrTask::{0}&resolve_system_metadata=true'.format(
            name
        ))


def send_results(results):
    """Send analysis results back to scumblr."""
    return request(
        '/tasks/{task_id}/run'.format(task_id=results['task_id']), data=results)


# TODO add retry logic here too?
def request(url, data=None):
    """Attempt to make a scumblr request."""
    with mktempfile() as tmpfile:
        with open(tmpfile, 'w') as f:
            f.write(get_secret("ENCRYPTED_SCUMBLR_KEY").decode('utf-8'))

        if data:
            data = json.dumps(data, indent=2)
            log.debug("Scumblr Request. URL: {0} Data: {1}".format(
                url,
                data
            ))

            response = requests.post(SCUMBLR_URL + url, cert=(
                SCUMBLR_CLIENT_PATH,
                tmpfile), data=data)
        else:
            log.debug("Scumblr Request. URL: {0}".format(
                url
            ))
            response = requests.get(SCUMBLR_URL + url, cert=(
                SCUMBLR_CLIENT_PATH,
                tmpfile))

    if not response.ok:
        log.debug(response.content)
        raise GeneralFailure("Request to Scumblr failed. URL: {0} Data: {1}".format(
            url, data
        ))

    log.debug("Scumblr Response. Status: {0} Data: {1}".format(
        response.status_code,
        json.dumps(response.json(), indent=2)
    ))

    return response.json()

