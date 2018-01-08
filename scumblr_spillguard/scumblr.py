import os
import json
import requests

from scumblr_spillguard import log
from scumblr_spillguard.utils import mktempfile
from scumblr_spillguard.secrets import get_secret
from scumblr_spillguard.exceptions import GeneralFailure

SCUMBLR_URL = os.environ["SCUMBLR_URL"]
SCUMBLR_CLIENT_PATH = os.environ.get("SCUMBLR_CLIENT_PATH", "SCUMBLR_CLIENT.cert")

CWD = os.path.dirname(os.path.realpath(__file__))


def get_config(name):
    """Return the current scumblr task configuration."""
    return request(
        '/tasks/search?q[task_type_eq]=ScumblrTask::{0}&resolve_system_metadata=true'.format(
            name
        ))


def send_results(task_id, results):
    """Send analysis results back to scumblr."""
    return request(
        '/tasks/{task_id}/run'.format(task_id=task_id), data=results)


# TODO add retry logic here too?
def request(url, data=None):
    """Attempt to make a scumblr request."""
    log.info("Making a request to Scumblr. URL: {0} Data: {1}".format(
        url, data
    ))

    with mktempfile() as tmpfile:
        with open(tmpfile, 'w') as f:
            f.write(get_secret("SCUMBLR_KEY").decode('utf-8'))

        if data:
            data = json.dumps(data)
            response = requests.post(SCUMBLR_URL + url, cert=(
                os.path.join(CWD, SCUMBLR_CLIENT_PATH),
                tmpfile), data=data)
        else:
            response = requests.get(SCUMBLR_URL + url, cert=(
                os.path.join(CWD, SCUMBLR_CLIENT_PATH),
                tmpfile))

    log.debug("Status Code: {}".format(response.status_code))

    if not response.ok:
        log.debug(response.content)
        raise GeneralFailure("Request to Scumblr failed. URL: {0} Data: {1}".format(
            url, data
        ))

    if not data:
        return response.json()

