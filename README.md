# Scumblr GithubSpillGuard
[![serverless](http://public.serverless.com/badges/v3.svg)](http://www.serverless.com)

A simple github webhook integration. Uses Scumblr as a source of terms to check incomming commits for. If a hit is found, sends the results to Scumblr for remediation.

The service has a dependency on external packages (`requests` and `retrying`) and it exposes 1 REST API endpoints:

| **Endpoint** |**Description**|
|-------|------|
| `POST /github` | Analyzes github commits based on Scumblr configuration  |


## Serverless Setup
| **Step** | **Command** |**Description**|
|---|-------|------|
|  1. | `npm install -g serverless` | Install Serverless CLI  |
|  2. | `npm install` | Install our package and it's dependencies |


## AWS Setup
Serverless requires different IAM credentials to deploy depending what infrastructure exists. If we assume that you have never used serverless before you will need `admin` credentials to deploy this lambda.

1. Create KMS Key
2. Create scumblr-spill-guard security group


## Configure serverless.yml
Replace variables in the `serverless.yml` with your own.

### KMS Encryption
To encrypt your variables, with your KMS key run:

`aws kms encrypt --key-id <YOUR-KEY-ID> --plaintext fileb://ExamplePlaintextFile --output text --query CiphertextBlob`


# Usage
## Deployment

	sls deploy

### Invocation

	curl <host>/github

# Tips & Tricks

### `help` command
Just use it on anything:

	sls  help
or

	sls <command> --help

### `deploy function` command
Deploy only one function:

	sls deploy function -f <function-name>

### `logs` command
Tail the logs of a function:

	sls logs -f <function-name> -t

### `info` command
Information about the service (stage, region, endpoints, functions):

	sls info

### `invoke` command
Run a specific function with a provided input and get the logs

	sls invoke -f <function-name> -p event.json -l


## Development
| **Step** | **Command** |**Description**|
|---|-------|------|
|  1. | `mkvirtualenv posts` | Create virtual environment |
|  2. | `pip install -r requirements.txt` | Install dependencies|


# Thanks
Big thanks to Jeremy for the project idea and initial implementation


