import requests
import re

from wazuh_testing.tools.exceptions import QAValueError


def _get_status_code(url):
    """Make a request to the specified URL and get its status code.

    Returns:
        int: Request status code
    """
    return (requests.get(url)).status_code


def _check_status_code(status_code, exception_message):
    """Check if the status code has an expected value.

    Parameters:
        status_code (int): Request status code.
        exception_message (str): Text to display in the exception message.

    Raises:
        Exception if status code is distinct from 200 and 400 (unexpected).

    """
    if status_code != 200 and status_code != 404:
        raise Exception(f"{exception_message}. Status code {status_code}")


def version_is_released(version, organization='wazuh', repository='wazuh'):
    """Check if the specified version has been released in the specified github repository.

    Parameters:
        version (str): Version to check.
        organization (str): Github repository organization name.
        repository (str): Github repository name.

    Returns:
        boolean: True if the version has been released, False otherwise.
    """
    v_version = f"v{version}" if 'v' not in version else version

    url = f"https://github.com/{organization}/{repository}/releases/tag/{v_version}"
    status_code = _get_status_code(url)

    _check_status_code(status_code, f"Could not check if {v_version} has been released. URL: {url}")

    return True if status_code == 200 else False


def branch_exists(branch_name, organization='wazuh', repository='wazuh'):
    """Check if the specified branch exists in the github repository.

    Parameters:
        branch_name (str): Branch name to check.
        organization (str): Github repository organization name.
        repository (str): Github repository name.

    Returns:
        boolean: True if branch exists in the github repository, False otherwise.

    """
    url = f"https://github.com/{organization}/{repository}/tree/{branch_name}"

    status_code = _get_status_code(url)

    _check_status_code(status_code, f"Could not check if {branch_name} exists. URL: {url}")

    return True if status_code == 200 else False


def get_last_wazuh_version():
    """Get the last Wazuh version that has been tagged, regardless of possible release candidate tags.

    Raises:
        QAValueError: If could not find a valid wazuh tag in the first github tags page (It can happen if on the first
                      page, all tags are rc tags.).
    Returns:
        str: Last Wazuh tag (no rc).
    """
    url = 'https://github.com/wazuh/wazuh/tags'
    req = requests.get(url)
    last_tags = re.findall(r'<a href="/wazuh/wazuh/releases/tag/v\d.\d.\d">', req.text)

    try:
        last_wazuh_version = re.compile(r'<a href="/wazuh/wazuh/releases/tag/v(\d.\d.\d)').search(last_tags[0]).group(1)
    except IndexError:
        raise QAValueError(f"Could not find a valid wazuh tag in {url}")

    return last_wazuh_version
