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
        file_content = base64.b64decode(contents["content"]).decode('utf-8', 'ignore')

        log.debug("Checking pattern {} '{}' against contents: {}".format(name, pattern, file_content))

        match = re.search(pattern, file_content, flags=re.MULTILINE | re.DOTALL)

        if match:
            log.debug("Contents hit on pattern {}".format(pattern))
            hits.append(name)

        else:
            log.debug("No hit on pattern {} for content {}".format(pattern, contents))

    return hits


def process_task_configs(commits, configs):
    """Iterates over all items in config analyzing each."""
    for config in configs:
        result = {
            'task_id': config['id'],
            'task_type': config['task_type'],
            'options': config['options'],
            'findings': []
        }

        for c in commits:
            hits = find_violations(c, config['options']['github_terms'])  # todo 'github_terms' should be generic 'terms'

            if hits:
                result['findings'].append(
                    {
                        'commit_id': c['id'],
                        'hits': hits,
                        'contents_url': c['']
                    }
                )

        log.debug("Results: {}".format(json.dumps(result, indent=2)))

        if result['findings']:
            scumblr.send_results(result)


@RavenLambdaWrapper()
def github(event, context):
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
    log.debug("Entering lambda handler with event: {}".format(json.dumps(event, indent=2)))

    github.validate(event)
    body = json.loads(event["body"])

    # get search terms from scumblr
    config = scumblr.get_config("GithubEventAnalyzer")

    log.debug("Body contains {} commits".format(len(body["commits"])))
    process_task_configs(body["commits"], config)

    return {"statusCode": "200", "body": "{}"}
