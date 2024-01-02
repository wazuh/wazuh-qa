# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import time
import requests
from base64 import b64encode

import wazuh_testing as fw
from urllib3 import disable_warnings, exceptions
from wazuh_testing.tools import file

disable_warnings(exceptions.InsecureRequestWarning)

# Variables

API_PROTOCOL = 'https'
API_HOST = 'localhost'
API_PORT = '55000'
API_USER = 'wazuh'
API_PASS = 'wazuh'
API_LOGIN_ENDPOINT = '/security/user/authenticate'


# Functions

def get_base_url(protocol, host, port):
    """Get complete url of api"""

    return f"{protocol}://{host}:{port}"


def get_login_headers(user, password):
    basic_auth = f"{user}:{password}".encode()
    return {'Content-Type': 'application/json',
            'Authorization': f'Basic {b64encode(basic_auth).decode()}'}


def get_token_login_api(protocol, host, port, user, password, login_endpoint, timeout, login_attempts, sleep_time):
    """Get API login token"""

    login_url = f"{get_base_url(protocol, host, port)}{login_endpoint}"

    for _ in range(login_attempts):
        response = requests.post(login_url, headers=get_login_headers(user, password), verify=False, timeout=timeout)

        if response.status_code == 200:
            return json.loads(response.content.decode())['data']['token']
        time.sleep(sleep_time)
    else:
        raise RuntimeError(f"Error obtaining login token: {response.json()}")


def get_api_details_dict(protocol=API_PROTOCOL, host=API_HOST, port=API_PORT, user=API_USER, password=API_PASS,
                         login_endpoint=API_LOGIN_ENDPOINT, timeout=10, login_attempts=1, sleep_time=0):
    """Get API details"""
    login_token = get_token_login_api(protocol, host, port, user, password, login_endpoint, timeout, login_attempts,
                                      sleep_time)
    return {
        'base_url': get_base_url(protocol, host, port),
        'auth_headers': {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {login_token}'
        }
    }


def get_security_resource_information(**kwargs):
    """Get all information about a security resource."""
    assert len(kwargs) == 1, f'This function only admits one argument'
    endpoint = {
        'user_ids': '/users?user_ids=',
        'role_ids': '/roles?role_ids=',
        'policy_ids': '/policies?policy_ids=',
        'rule_ids': '/rules?rule_ids=',
    }

    api_details = get_api_details_dict()
    resource = next(iter(kwargs.keys()))
    value = kwargs[resource]
    value = ','.join(value) if isinstance(value, list) else value
    get_endpoint = api_details['base_url'] + '/security' + endpoint[resource] + str(value)

    response = requests.get(get_endpoint, headers=api_details['auth_headers'], verify=False)

    if response.json()['error'] == 0:
        return response.json()['data']['affected_items'][0]
    else:
        return {}


def compare_config_api_response(configuration, section):
    """Assert if configuration values provided are the same that configuration provided for API response.

    Args:
        configuration (dict): Dictionary with Wazuh manager configuration.
        section (str): Section to compare.
    """
    api_answer = get_manager_configuration(section=section)
    assert type(api_answer) == type(configuration)

    if isinstance(api_answer, list):
        configuration_length = len(configuration)
        for i in range(configuration_length):
            api_answer_to_compare = dict((key, api_answer[i][key]) for key in configuration[i].keys())
            assert api_answer_to_compare == configuration[i]
    else:
        api_answer_to_compare = dict((key, api_answer[key]) for key in configuration.keys())
        assert api_answer_to_compare == configuration


def get_manager_configuration(section=None, field=None):
    """Get Wazuh manager configuration response from API using GET /manager/configuration

    References: https://documentation.wazuh.com/current/user-manual/api/reference.html#operation/
                api.controllers.manager_controller.get_configuration

    Args:
        section (str): wazuh configuration section, E.g: "active-response", "ruleset"...
        field   (str): section child. E.g, fields for ruleset section are: decoder_dir, rule_dir, etc

    Returns:
        `obj`(str or map): active configuration indicated by Wazuh API. If section and field are selected, it will
         return a String, if not, it will return a map for the section/entire configurations with fields/sections
         as keys.
    """
    api_details = get_api_details_dict()
    api_query = f"{api_details['base_url']}/manager/configuration?"

    if section is not None:
        api_query += f"section={section}"
        if field is not None:
            api_query += f"&field={field}"

    response = requests.get(api_query, headers=api_details['auth_headers'], verify=False)

    assert response.json()['error'] == 0, f"Wazuh API response status different from 0: {response.json()}"
    answer = response.json()['data']['affected_items'][0]

    def get_requested_values(answer, section, field):
        """Return requested value from API response

        Received a section and a field and tries to return all available values that match with this entry.
        This function is required because, sometimes, there may be multiple entries with the same field or section
        and the API will return a list instead of a map. Using recursion we make sure that the output matches
        the user expectations.
        """
        if isinstance(answer, list):
            new_answer = []
            for element in answer:
                new_answer.append(get_requested_values(element, section, field))
            return new_answer
        elif isinstance(answer, dict):
            if section in answer.keys():
                new_answer = answer[section]
                return get_requested_values(new_answer, section, field)
            if field in answer.keys():
                new_answer = answer[field]
                return get_requested_values(new_answer, section, field)
        return answer

    return get_requested_values(answer, section, field)


def wait_until_api_ready(protocol=API_PROTOCOL, host=API_HOST, port=API_PORT, user=API_USER, password=API_PASS,
                         login_endpoint=API_LOGIN_ENDPOINT, timeout=10, attempts=5):
    """Wait until Wazuh API is ready

    Args:
        protocol (str): Used protocol for Wazuh manager.
        host (str): Wazuh manager host ip.
        port (str): Wazuh manager port.
        user (str): API user.
        password (str): API password.
        login_endpoint (str): API login endpoint.
        timeout (int): Timeout to get an API response.
        attempts (int): Maximum number of attempts to check API is ready.
    """

    get_token_login_api(protocol, host, port, user, password, login_endpoint, timeout, attempts, 1)


def make_api_call(manager_address=API_HOST, port=55000, method='GET', endpoint='/', headers=None, request_json=None,
                  params=None, verify=False, token=None):
    """Make an API call

    Args:
        port (str, optional): Wazuh manager port.
        method (str, optional): Request method. Default `GET`
        endpoint (str, optional): Request endpoint. It must start with '/'.. Default `/`
        headers (dict, optional): request headers. Default `None`
        request_json ( dict, optional) : Request body. Default `None`
        params ( dict, optional) : Request params. Default `None`
        verify ( bool, optional): Request verify. Default `False`
        token (str, optional): API auth token. Default `None` cannot be None if headers is None or missing the
                               Authorization header.

    Returns: response dict.
    """
    if headers is None and token is None:
        return "Request Error - No authorization information passed."
    elif headers is None:
        headers = {'Authorization': f"Bearer {token}"}
    if 'Authorization' not in headers.keys():
        headers['Authorization'] = f"Bearer {token}"

    response = None
    if method == 'POST':
        response = requests.post(f'https://{manager_address}:{port}{endpoint}', headers=headers, json=request_json,
                                 params=params, verify=verify)
    elif method == 'DELETE':
        response = requests.delete(f'https://{manager_address}:{port}{endpoint}', headers=headers, json=request_json,
                                   params=params, verify=verify)
    elif method == 'PUT':
        response = requests.put(f'https://{manager_address}:{port}{endpoint}', headers=headers, json=request_json,
                                params=params, verify=verify)
    else:
        response = requests.get(f'https://{manager_address}:{port}{endpoint}', headers=headers, json=request_json,
                                params=params, verify=verify)
    return response


def create_groups_api_request(group, token):
    """ Make API call to create a specified group
    Args:
        group (str): name of the group that will be created.
        token (str): API auth token.

    Returns: API call response.
    """
    headers = {'Authorization': f"Bearer {token}"}
    json_data = {'group_id': f"{group}"}
    endpoint = '/groups'
    response = make_api_call(method='POST', endpoint=endpoint, headers=headers, request_json=json_data)
    return response


def set_up_groups(groups_list):
    """ Make API calls to create a series of groups
    Args:
        group_list (List<str>): List containing the names of the groups to create.

    Returns: None
    """
    response_token = get_token_login_api(API_PROTOCOL, API_HOST, API_PORT, API_USER, API_PASS, API_LOGIN_ENDPOINT,
                                         timeout=10, login_attempts=3, sleep_time=1)

    for group in groups_list:
        response = create_groups_api_request(group, response_token)


def remove_groups():
    """ Makes API call to remove all groups from the manager

    Returns: API call response
    """
    response_token = get_token_login_api(API_PROTOCOL, API_HOST, API_PORT, API_USER, API_PASS, API_LOGIN_ENDPOINT,
                                         timeout=10, login_attempts=3, sleep_time=1)
    headers = {'Authorization': f"Bearer {response_token}"}
    params = (
        ('pretty', 'true'),
        ('groups_list', 'all'),
    )
    endpoint = '/groups'
    response = make_api_call(method="DELETE", endpoint=endpoint, headers=headers, params=params)
    return response


def clean_api_log_files():
    """ Clean all the logs files and delete the ones that have been rotated."""
    file.remove_file(fw.API_LOG_FOLDER)
    log_files = [fw.API_LOG_FILE_PATH, fw.API_JSON_LOG_FILE_PATH]
    for log_file in log_files:
        file.truncate_file(log_file)
