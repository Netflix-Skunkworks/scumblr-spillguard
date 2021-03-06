import re
import json
import base64
from raven_python_lambda import RavenLambdaWrapper

from scumblr_spillguard import log
from scumblr_spillguard import scumblr, github, bitbucket


def find_violations(contents, terms):
    """Find any violations in a given file."""
    hits = []

    for name, pattern in terms.items():
        match = re.search(pattern, contents, flags=re.MULTILINE | re.DOTALL)

        if match:
            log.debug("Contents hit on pattern {}".format(pattern))
            hits.append(name)

    return hits


def process_task_configs(commit, configs):
    """Iterates over all items in config analyzing each.

    Scumblr expects the following format::

    {
      "task_id": 105,
      "config": {
        "id": 105,
        "task_type": "ScumblrTask::GithubEventAnalyzer",
        "options": {
          "severity": "high",
          "github_terms": {
            "exec": "ProcessUtil.getRuntime().exec",
            "exec1": "Runtime.getRuntime().exec",
            "slack token": "xoxb",
            "slack token1": "xoxp-"
          }
        }
      },
      "commit": {
        "ref": "refs/heads/master",
        "head_commit": {
          "committer": {
            "name": "GitHub",
            "email": "noreply@github.com",
            "username": "web-flow"
          }
        },
        "repository": {
          "html_url": "https://github.com/Netflix-Skunkworks/test-gh-spillguard"
        }
      },
      "hits": true,
      "findings": [
        {
          "commit_id": "74ff78c232c8d8516f42c69767d30b5ef37e4041",
          "findings": [
            {
              "content_urls": "https://api.github.com/repos/Netflix-Skunkworks/test-gh-spillguard/contents/test1?ref=74ff78c232c8d8516f42c69767d30b5ef37e4041",
              "hits": [
                "slack token"
              ]
            }
          ]
        }
      ]
    }

    """
    for config in configs:
        result = {
            'task_id': config['id'],
            'task_type': config['task_type'],
            'findings': [],
            'config': {
                'id': config['id'],
                'task_type': config['task_type'],
                'options': config['options']
            },
            'commit': {
                'ref': commit['ref'],
                'head_commit': {
                    'committer': commit['committer']
                },
                'repository': {'html_url': commit['html_url']}
            }
        }

        log.info('Working on config. Config: {0}'.format(
            json.dumps(config, indent=2)
        ))

        hits = find_violations(commit['contents'],
                               config['options']['github_terms'])  # todo 'github_terms' should be generic 'terms'

        if hits:
            result['findings'].append(
                {
                    'commit_id': commit['sha'],
                    'findings': [
                        {
                            'hits': hits,
                            'content_urls': commit['contents_url'].split('?')[0]
                        }
                    ]}
            )

        if result['findings']:
            log.error('Has findings. Sending result to scumblr. Result: {0}'.format(json.dumps(result, indent=2)))
            scumblr.send_results(result)

        log.warning('Finished working on config. Result: {0}'.format(
            json.dumps(result, indent=2),
        ))


@RavenLambdaWrapper()
def github_handler(event, context):
    """
    Handles the processing of Github commit events.

    The general flow of processing is as follows::

    1) Receive Github Webhook event.
    2) Validate event for SourceIp, User-Agent and HMAC digest using a pre-shared secret.
    3) Fetch terms from Scumblr for processing.
    4) Fetch commit information from Github.
    5) Fetch full file information via the blob api.
    6) Analyze blob with terms defined by the Scumblr configuration.
    7) Return analysis results to Scumblr.
    """
    log.debug('Entering lambda handler with event: {}'.format(json.dumps(event, indent=2)))

    # github has a very low timeout (10s) we make sure that we can prewarm our function to prevent
    # the service from timing out
    if event.get('source') == 'aws.events':
        return {'statusCode': '200', 'body': '{}'}

    github.validate(event)
    body = json.loads(event['body'])

    commit_url = body['repository']['commits_url'][:-len('{/sha}')]
    blobs_url = body['repository']['blobs_url'][:-len('{/sha}')]

    # get search terms from scumblr
    config = scumblr.get_config('GithubEventAnalyzer')

    log.debug('Body contains {} commits'.format(len(body['commits'])))

    for c in body['commits']:
        commit_data = github.request(commit_url + '/' + c['id'])

        for f in commit_data['files']:
            data = github.request(blobs_url + '/' + f['sha'])['content']
            try:
                commit_data['contents'] = base64.b64decode(data).decode('utf-8', 'ignore')
                commit_data['contents_url'] = f['contents_url']
                commit_data['committer'] = c['committer']
                commit_data['ref'] = body['ref']
                commit_data['html_url'] = body['repository']['html_url']
            except Exception as e:
                log.exception(e)
                continue

            process_task_configs(commit_data, config)

    return {'statusCode': '200', 'body': '{}'}


@RavenLambdaWrapper()
def rocketci_handler(event, context):
    """
    Handles processing of RocketCI commit events.

    The general flow of processing is as follows::

    1) Receive RocketCI event.
    2) Fetch terms from Scumblr for processing.
    3) Fetch commit information from Stash/Bitbucket.
    4) Fetch full file information via api.
    5) Analyze blob with terms defined by the Scumblr configuration.
    6) Return analysis results to Scumblr.

    :param event:
    :param context:
    :return:
    """
    log.debug('Entering lambda handler with event: {}'.format(json.dumps(event, indent=2)))
    for r in event['Records']:
        body = json.loads(r['Sns']['Message'])
        if body.get('eventSource') == 'stash-stable':
            if body.get('codeEventType') == 'create_commit':
                # get search terms from scumblr
                log.debug('Got Message: {}'.format(json.dumps(body, indent=2)))
                config = scumblr.get_config('GithubEventAnalyzer')  # TODO separate out terms
                commit_data = bitbucket.request(body['source']['url'] + '/' + 'changes')

                for f in commit_data['values']:
                    file_url = bitbucket.get_file_url(f['links']['self'][0]['href'])
                    data = bitbucket.reconstruct_contents(bitbucket.request(file_url))

                    # normalize commit data
                    commit_data['contents'] = data
                    commit_data['contents_url'] = file_url
                    commit_data['sha'] = body['source']['sha']
                    commit_data['committer'] = body['source']['author']['email']
                    commit_data['ref'] = body['source']['refId']
                    commit_data['html_url'] = body['source']['url']

                    # send to scumblr
                    process_task_configs(commit_data, config)

    return {'statusCode': '200', 'body': '{}'}


@RavenLambdaWrapper()
def bitbucket_handler(event, context):
    """
    Handles processing of bitbucket commit events.

    The general flow of processing is as follows::

    1) Receive Bitbucket Webhook.
    2) Validate event for SourceIp, User-Agent and HMAC digest using a pre-shared secret.
    3) Fetch terms from Scumblr for processing.
    4) Fetch commit information from Stash.
    5) Fetch full file information via the blob api.
    6) Analyze blob with terms defined by the Scumblr configuration.
    7) Return analysis results to Scumblr.

    :param event:
    :param context:
    :return:
    """
    raise NotImplementedError
