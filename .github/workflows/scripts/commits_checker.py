import argparse
import re
import requests
import sys

from http import HTTPStatus


RED = '\033[91m'
GREEN = '\033[92m'
CLEAR_COLOR = '\033[0m'


def get_script_parameters():
    """Process the script parameters.

    Returns:
        ArgumentParser: Parameters and their values.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--pr-number', '-p', type=str, action='store', required=True, dest='pr_number',
                        help='PR number')
    parser.add_argument('--token', '-t', type=str, action='store', required=True, dest='github_token',
                        help='Github token')

    script_parameters = parser.parse_args()

    return script_parameters


def get_PR_data(pr_number, github_token):
    """Get the pull request data from the Github API.

    Args:
        pr_number (str): PR number.
        github_token (str): Github token.

    Returns:
        dict: PR data.
    """
    github_api_url = 'https://api.github.com'
    query = f"/repos/wazuh/wazuh-qa/pulls/{pr_number}/commits"
    headers = {'Accept': 'application/vnd.github.v3+json', 'Authorization': f"token {github_token}"}

    response = requests.get(f"{github_api_url}{query}", headers=headers)

    if response.status_code != HTTPStatus.OK:
        print(f"Fail when requesting to {github_api_url}{query}. Status code {response.status_code}")
        sys.exit(1)

    response_data = response.json()
    page = 1

    # Iterate over response pages and group all the information
    while 'next' in response.links.keys():
        response = requests.get(response.links['next']['url'], headers=headers)
        if response.status_code != HTTPStatus.OK:
            print(f"Fail when requesting to {github_api_url}{query} page {page}. Status code {response.status_code}")
            sys.exit(1)

        response_data.extend(response.json())
        page += 1

    return response_data


def check_conventional_commits_regex(commit_names):
    """Check if the commit name complies the convention.

    Args:
        commit_names (list(str)): Commit names.

    Returns:
        int, list(): Result code and failed data.
    """
    failed = [[], []]  # Position 0 for convention failures, and 1 for excess character limit
    allowed_regex = [
        r'(fix|feat|docs|refactor|style|ci|build|merge|revert)(\(#\d+\))?!?:\s.*'
    ]

    # Check if the commit name complies with the established convention
    for commit_name in commit_names:
        for regex in allowed_regex:
            if bool(re.match(regex, commit_name)):
                break
        else:
            failed[0].append(commit_name)

    # Check if commit name exceeds the 75 characters
    for commit_name in commit_names:
        if len(commit_name) > 75 and not bool(re.match(r'^Merge branch.*', commit_name)):
            failed[1].append(commit_name)

    # Calculate the result code
    result_code = 0 if len(failed[0]) == 0 and len(failed[1]) == 0 else 1

    return result_code, failed


def main():
    script_parameters = get_script_parameters()

    # Get PR data
    pr_data = get_PR_data(script_parameters.pr_number, script_parameters.github_token)
    pr_commit_names = [item['commit']['message'].split('\n')[0] for item in pr_data]

    # Validate the PR commit names
    result, failed_commits = check_conventional_commits_regex(pr_commit_names)

    if result == 0:
        print(f"{GREEN}All commit names are valid{CLEAR_COLOR}")
    else:
        if len(failed_commits[0]) > 0:
            print('=' * 100)
            print(f"{RED}The following commits do not comply with the conventional commits specification:")
            for failed_commit in failed_commits[0]:
                print(f"{RED}{failed_commit}{CLEAR_COLOR}")

        if len(failed_commits[1]) > 0:
            print('=' * 100)
            print(f"{RED}The following commits exceed the limit of allowed characters (>75)")
            for failed_commit in failed_commits[1]:
                print(f"{RED}{failed_commit}{CLEAR_COLOR}")

        sys.exit(1)


if __name__ == '__main__':
    main()
