#!/usr/bin/python3

import argparse
import requests
from http import HTTPStatus


def get_parameters():
    """
    Returns:
        argparse.Namespace: Object with the user parameters.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--token', '-t', type=str, action='store', required=True)
    parser.add_argument('--channel', '-c', type=str, action='store', required=True)
    parser.add_argument('--messages-limit', '-m', type=int, action='store', required=True)
    parser.add_argument('--path', '-p', type=str, action='store', required=True)

    arguments = parser.parse_args()

    return arguments


def main():
    # Obtain user-specified parameters from the command line
    parameters = get_parameters()

    headers = {'Authorization': f"Bearer {parameters.token}", 'content-type': 'application/json', 'charset': 'utf8'}
    url = 'https://slack.com/api/conversations.history'
    payload = {'channel': parameters.channel, 'limit': parameters.messages_limit}

    # Get the last N messages from a Slack channel
    response = requests.get(url, params=payload, headers=headers)

    # Check if the response is as expected
    if response.status_code != HTTPStatus.OK or "'ok': False" in response.text:
        raise Exception(f"There was an error while trying to get the messages from channel: {response.text}")

    # Write the messages obtained from Slack to a flat file
    with open(parameters.path, 'w') as messages_log:
        messages_log.write(response.text)


if __name__ == '__main__':
    main()
