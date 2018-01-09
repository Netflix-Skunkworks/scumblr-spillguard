import re
import json
import base64
from raven_python_lambda import RavenLambdaWrapper

from scumblr_spillguard import log
from scumblr_spillguard import scumblr, github


def find_violations(contents, terms):
    """Find any violations in a given file."""
    hits = []

    for name, pattern in terms.items():
        log.debug("Checking pattern {} '{}' against contents: {}".format(name, pattern, file_content))

        match = re.search(pattern, contents, flags=re.MULTILINE | re.DOTALL)

        if match:
            log.debug("Contents hit on pattern {}".format(pattern))
            hits.append(name)

        else:
            log.debug("No hit on pattern {} for content {}".format(pattern, contents))

    return hits


def process_task_configs(commit, configs):
    """Iterates over all items in config analyzing each."""
    for config in configs:
        result = {
            'task_id': config['id'],
            'task_type': config['task_type'],
            'options': config['options'],
            'findings': []
        }

        log.info('Working on config. Config: {0}'.format(
            json.dumps(config, indent=2)
        ))

        hits = find_violations(commit['contents'], config['options']['github_terms'])  # todo 'github_terms' should be generic 'terms'

        if hits:
            result['findings'].append(
                {
                    'commit_id': commit['sha'],
                    'hits': hits,
                    'contents_url': commit['contentsUrl']
                }
            )

        if result['findings']:
            scumblr.send_results(result)

        log.info('Finished working on config. Config: {0} Result: {1}, Commit: {2}'.format(
            json.dumps(config, indent=2),
            json.dumps(result, indent=2),
            json.dumps(commit, indent=3)
        ))


@RavenLambdaWrapper()
def github_handler(event, context):
    """
    Handles the processing of Github commit events.

    The general flow of processing is as follows:

    1) Receive Github Webhook event.
    2) Validate event for SourceIp, User-Agent and HMAC digest using a pre-shared secret.
    3) Fetch terms from Scumblr for processing.
    4) Fetch commit information from Github.
    5) Fetch full file information via the blob api.
    6) Analyze blob with terms defined by the Scumblr configuration.
    7) Return analysis results to Scumblr.
    """
    log.debug('Entering lambda handler with event: {}'.format(json.dumps(event, indent=2)))

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
            except Exception as e:
                log.exception(e)
                continue

            process_task_configs(commit_data, config)

    return {'statusCode': '200', 'body': '{}'}
