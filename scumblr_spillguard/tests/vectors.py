SCUMBLR_URL = 'http://scumblr.test'
GITHUB_URL = 'http://api.github.com'

GITHUB_SCUMBLR_CONFIG_RESPONSE = [{
    'id': 105,
    'task_type': 'ScumblrTask::GithubEventAnalyzer',
    'options': {
        'severity': 'high',
        'github_terms': {
            'exec': 'ProcessUtil.getRuntime().exec',
            'exec1': 'Runtime.getRuntime().exec',
            'slack token': 'xoxb',
            'slack token1': 'xoxp-'
        }
    }
}]

GITHUB_SCUMBLR_RESULT = {
    'task_id': 105,
    'config': GITHUB_SCUMBLR_CONFIG_RESPONSE[0],
    'findings': [
        {
            'commit_id': '779e77e65338156c35f8e053d54f696d464a32e6',
            'findings': [{
                'content_urls': 'https://api.github.com/repos/Netflix-Skunkworks/test-gh-spillguard/contents/kevin?ref=779e77e65338156c35f8e053d54f696d464a32e6',
                'hits': ['slack token']
            }]
        }]
}

GITHUB_APIGATEWAY_EVENT = {
    'resource': '/github',
    'headers': {
        'X-Hub-Signature': 'sha1=6af368b8a04b7a39d6469ef4faaab2721f07f177'
    },
    'requestContext': {
        'identity': {
            'sourceIp': '192.30.252.3'
        }
    },
    'body': {
        'sha': '6af368b8a04b7a39d6469ef4faaab2721f07f177',
        'size': 91,
        'url': 'https://api.github.com/repos/Netflix-Skunkworks/test-gh-spillguard/git/blobs/6af368b8a04b7a39d6469ef4faaab2721f07f177',
        'content': 'YWxrZmphc2RrbGZhanMKc2FmbGtmc2FqbGtmYXNqeG94Yi0KCmxmYXNqbGtm\nYWpmc2EKZnNhbGtzYWZqbGtmYWpzCmZzYWpmc2FrbGpmc2Fsa3NhZgp0ZXN0\nCg==\n',
        'encoding': 'base64'
    }
}

GITHUB_COMMIT_RESPONSE = {
    'sha': '779e77e65338156c35f8e053d54f696d464a32e6',
    'url': 'https://api.github.com/repos/Netflix-Skunkworks/test-gh-spillguard/commits/779e77e65338156c35f8e053d54f696d464a32e6',
    'files': [
        {
            'sha': '6af368b8a04b7a39d6469ef4faaab2721f07f177',
            'blob_url': 'https://github.com/Netflix-Skunkworks/test-gh-spillguard/blob/779e77e65338156c35f8e053d54f696d464a32e6/kevin',
            'raw_url': 'https://github.com/Netflix-Skunkworks/test-gh-spillguard/raw/779e77e65338156c35f8e053d54f696d464a32e6/kevin',
            'contents_url': 'https://api.github.com/repos/Netflix-Skunkworks/test-gh-spillguard/contents/kevin?ref=779e77e65338156c35f8e053d54f696d464a32e6',
            'patch': '@@ -4,3 +4,4 @@ saflkfsajlkfasjxoxb-\n lfasjlkfajfsa\n fsalksafjlkfajs\n fsajfsakljfsalksaf\n+test'
        }
    ]
}

ROCKETCI_SNS_EVENT = {}

BITBUCKET_APIGATEWAY_EVENT = {}
