import pytest
from scumblr_spillguard.tests.vectors import *
from scumblr_spillguard.exceptions import *


def generate_github_hmac(event):
    import hmac
    import json
    import hashlib
    from scumblr_spillguard.secrets import get_secret

    message_hmac = hmac.new(
        get_secret('WEBHOOK_SECRET'),
        json.dumps(event['body']).encode('utf-8'),
        hashlib.sha1
    )

    event['headers']['X-Hub-Signature'] = 'sha1=' + message_hmac.hexdigest()
    return event


def test_scumblr_get_config(mocked_env, github_scumblr_config):
    from scumblr_spillguard.scumblr import get_config
    assert get_config('GithubEventAnalyzer') == GITHUB_SCUMBLR_CONFIG_RESPONSE


def test_scumblr_send_results(mocked_env, github_scumblr_result):
    from scumblr_spillguard.scumblr import send_results
    assert send_results() == {}


def test_github_validate(mocked_env):
    from scumblr_spillguard.github import validate
    validate(generate_github_hmac(GITHUB_APIGATEWAY_EVENT))

    with pytest.raises(AuthorizationError):
        e = GITHUB_APIGATEWAY_EVENT.copy()
        e['requestContext']['identity']['sourceIp'] = '192.168.1.1'
        validate(e)


def test_github_authorize(mocked_env):
    from scumblr_spillguard.github import authorize

    e = generate_github_hmac(GITHUB_APIGATEWAY_EVENT)
    authorize(e['body'], e['headers'], e['requestContext']['identity']['sourceIp'])

