import os
import boto3
import pytest
import responses

from moto import mock_kms

from scumblr_spillguard.tests.vectors import *


@pytest.fixture(scope='function')
def mocked_env():
    os.environ["SCUMBLR_URL"] = SCUMBLR_URL
    os.environ["SCUMBLR_CERT_PATH"] = '.'

    with mock_kms():
        client = boto3.client('kms')
        os.environ["WEBHOOK_SECRET"] = client.encrypt(
            KeyId='1234abcd-12ab-34cd-56ef-1234567890ab',
            Plaintext=b'bytes'
        )['CiphertextBlob'].decode('utf-8')
        os.environ["GITHUB_OAUTH_TOKEN"] = client.encrypt(
            KeyId='1234abcd-12ab-34cd-56ef-1234567890ac',
            Plaintext=b'bytes'
        )['CiphertextBlob'].decode('utf-8')

        os.environ["GITHUB_OAUTH_TOKEN"] = client.encrypt(
            KeyId='1234abcd-12ab-34cd-56ef-1234567890ae',
            Plaintext=b'bytes'
        )['CiphertextBlob'].decode('utf-8')

        os.environ["SCUMBLR_KEY"] = client.encrypt(
            KeyId='1234abcd-12ab-34cd-56ef-1234567890af',
            Plaintext=b'bytes'
        )['CiphertextBlob'].decode('utf-8')
        yield


@pytest.fixture(scope='function')
def mocked_responses():
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield rsps


@pytest.fixture(scope='function')
def github_scumblr_config(mocked_responses):
    url = '{}/tasks/search?q[task_type_eq]=ScumblrTask::GithubEventAnalyzer&resolve_system_metadata=true'

    mocked_responses.add(
        responses.GET,
        url.format(SCUMBLR_URL),
        json=GITHUB_SCUMBLR_CONFIG_RESPONSE,
        status=200
    )


@pytest.fixture(scope='function')
def github_scumblr_result(mocked_responses):
    url = '{}/tasks/105/run'

    mocked_responses.add(
        responses.POST,
        url.format(SCUMBLR_URL),
        json={},
        status=200
    )


@pytest.fixture(scope='function')
def github_blob_response(mocked_responses):
    url = '{}/'

    mocked_responses.add(
        responses.GET,
        url.format(GITHUB_URL),
        json=GITHUB_BLOB_RESPONSE,
        status=200
    )


@pytest.fixture(scope='function')
def github_commit_response(mocked_responses):
    url = '{}'
    mocked_responses.add(
        responses.GET,
        url.format(GITHUB_URL),
        json=GITHUB_COMMIT_RESPONSE,
        status=200
    )
