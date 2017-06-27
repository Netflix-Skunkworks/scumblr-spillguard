#!/usr/bin/env python
import os
import re
import hmac
import json
import base64
import logging
import hashlib
import ipaddress
import tempfile
from contextlib import contextmanager

import boto3
import requests
from retrying import retry

logging.basicConfig()
log = logging.getLogger("ScumblrSpillGuard")
log.setLevel(logging.INFO)
SCUMBLR_URL = os.environ["SCUMBLR_URL"]

GITHUB_CIDR_WHITELIST = ["192.30.252.0/22", "185.199.108.0/22"]

CWD = os.path.dirname(os.path.realpath(__file__))

kms = boto3.session.Session().client("kms")
GITHUB_OAUTH_TOKEN = kms.decrypt(CiphertextBlob=base64.b64decode(os.environ["ENCRYPTED_GITHUB_TOKEN"]))["Plaintext"]
WEBHOOK_SECRET = kms.decrypt(CiphertextBlob=base64.b64decode(os.environ["ENCRYPTED_WEBHOOK_SECRET"]))["Plaintext"]
SCUMBLR_KEY = kms.decrypt(CiphertextBlob=base64.b64decode(os.environ["ENCRYPTED_SCUMBLR_KEY"]))["Plaintext"]


class GeneralFailure(Exception):
    pass


class AuthenticationError(GeneralFailure):
    pass


class AuthorizationError(GeneralFailure):
    pass


class ThrottledError(GeneralFailure):
    pass


def github_thottled(exception):
    """We should retry if we think we can successfully complete the request within the lambda timeout."""
    log.exception(exception)
    return isinstance(exception, ThrottledError)


@contextmanager
def mktempfile():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        name = f.name
    try:
        yield name
    finally:
        try:
            os.unlink(name)
        except OSError as e:
            log.debug("No file {0}".format(name))


@retry(retry_on_exception=github_thottled, wait_random_min=1000, wait_random_max=10000)
def github_request(url):
    """Attempt to make a Github request."""
    params = {"access_token": GITHUB_OAUTH_TOKEN}

    log.info("Checking url {}".format(url))

    response = requests.get(url, params=params)

    if not response.ok:
        raise GeneralFailure("Request to Github failed. URL: {0}".format(url))

    log.info("Github response: {}".format(response.json()))

    if response.headers['X-RateLimit-Remaining'] == 0:
        log.info("Throttled by Github. X-RateLimit-Limit: {0}".format(
            response.headers['X-RateLimit-Limit']))
        raise ThrottledError()

    return response.json()


# TODO add retry logic here too?
def scumblr_request(url, data=None):
    """Attempt to make a scumblr request."""
    log.info("Making a request to Scumblr. URL: {0} Data: {1}".format(
        url, data
    ))

    with mktempfile() as tmpfile:
        with open(tmpfile, 'w') as f:
            f.write(SCUMBLR_KEY.decode('utf-8'))

        if data:
            data = json.dumps(data)
            response = requests.post(SCUMBLR_URL + url, cert=(
                os.path.join(CWD, 'SCUMBLR_CLIENT.cert'),
                tmpfile), data=data)
        else:
            response = requests.get(SCUMBLR_URL + url, cert=(
                os.path.join(CWD, 'SCUMBLR_CLIENT.cert'),
                tmpfile))

    log.debug("Status Code: {}".format(response.status_code))

    if not response.ok:
        log.debug(response.content)
        raise GeneralFailure("Request to Scumblr failed. URL: {0} Data: {1}".format(
            url, data
        ))

    if not data:
        return response.json()


def valid_ip(source_ip):
    """Determine if we are getting a request from a github webhook."""
    log.debug("Validating source IP")
    for cidr in GITHUB_CIDR_WHITELIST:
        if ipaddress.IPv4Address(source_ip) in ipaddress.IPv4Network(cidr):
            log.debug("{} is in {}".format(source_ip, cidr))
            return True
        else:
            log.debug("{} is NOT in {}".format(source_ip, cidr))

    raise AuthorizationError()


def check_authorization(body, sig, source_ip):
    """Attempt to determine if the web hook call is a valid one."""
    valid_ip(source_ip)
    message_hmac = hmac.new(WEBHOOK_SECRET, body.encode('utf-8'), hashlib.sha1).hexdigest()
    log.debug("Computed HMAC: {} Actual HMAC: {}".format(message_hmac, sig))

    sig = sig.split('=')[1]

    if not hmac.compare_digest(sig, message_hmac):
        log.debug("Computed HMAC {} does not match passed signature {}".format(message_hmac, sig))
        raise AuthorizationError()

    log.debug("Computed HMAC {} does MATCHES passed signature {}".format(message_hmac, sig))
    return True


def find_violations(file, terms):
    """Find any violations in a given file."""
    contents_url = file["contents_url"]
    log.debug("Grabbing content {}".format(contents_url))

    contents = github_request(contents_url)
    hits = []

    for name, pattern in terms.items():
        file_content = base64.b64decode(contents["content"]).decode('utf-8')

        log.debug("Checking pattern {} '{}' against contents: {}".format(name, pattern, file_content))

        match = re.search(pattern, file_content, flags=re.MULTILINE | re.DOTALL)

        if match:
            log.debug("Contents hit on pattern {}".format(pattern))
            hits.append(name)

        else:
            log.debug("No hit on pattern {} for content {}".format(pattern, contents_url))

    return hits


def analyze_commits(body, config):
    """Determine if commit has any violations."""
    commit_url = body["repository"]["commits_url"][:-len("{/sha}")]

    commit_results = []

    for commit in body.get("commits"):
        commit_id = commit["id"]
        url = "{base}/{id}".format(base=commit_url, id=commit_id)

        commit_info = github_request(url)

        file_findings = []

        for f in commit_info["files"]:
            terms = config["options"]["github_terms"]
            hits = find_violations(f, terms)

            if len(hits):
                file_findings.append({"content_urls": f["contents_url"], "hits": hits})

        if len(file_findings):
            commit_results.append({"commit_id": commit_id, "findings": file_findings})

    results = {"task_id": config["id"], "config": config, "commit": body, "hits": False, "findings": None}

    if len(commit_results):
        results.update({"hits": True, "findings": commit_results})

    log.debug("results: {}".format(json.dumps(results, indent=2)))
    return results


def validate_event(event):
    """Ensure the incoming event is what we expect."""
    if event.get("resource") == "/github":
        if event.get("requestContext"):
            if event["requestContext"].get("identity"):
                if event["requestContext"]["identity"].get("userAgent"):
                    if event["requestContext"]["identity"]["userAgent"].startswith("GitHub-Hookshot"):
                        return True

    raise GeneralFailure("Invalid event. Event: {}".format(event))


def github(event, context):
    log.debug("Entering lambda handler with event: {}".format(json.dumps(event, indent=2)))

    validate_event(event)
    log.info("Processing GitHub web hook event")

    check_authorization(
       body=event["body"],
       sig=event["headers"]["X-Hub-Signature"],
       source_ip=event["requestContext"]["identity"]["sourceIp"]
    )

    body = json.loads(event["body"])

    # get search terms from scumblr
    config = scumblr_request(
        '/tasks/search?q[task_type_eq]=ScumblrTask::GithubEventAnalyzer&resolve_system_metadata=true')

    log.info("Body contains {} commits".format(len(body["commits"])))

    for item in config:
        results = analyze_commits(body, item)

        log.info("Results: {}".format(json.dumps(results, indent=2)))

        if results['hits']:
            # post the results
            scumblr_request(
                '/tasks/{task_id}/run'.format(task_id=results['task_id']),
                data=results)

    return {"statusCode": "200", "body": "{}"}
