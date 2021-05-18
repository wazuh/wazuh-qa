# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import re
import time
from base64 import b64encode

import requests
from urllib3 import disable_warnings, exceptions
disable_warnings(exceptions.InsecureRequestWarning)

# Variables

API_PROTOCOL = 'https'
API_HOST = 'localhost'
API_PORT = '55000'
API_USER = 'wazuh'
API_PASS = 'wazuh'
API_LOGIN_ENDPOINT = '/security/user/authenticate'


# Callbacks

def callback_detect_api_start(line):
    match = re.match(r'.*INFO: Listening on (.+)..', line)
    if match:
        return match.group(1)


def callback_detect_api_debug(line):
    match = re.match(r'.*DEBUG: (.*)', line)
    if match:
        return match.group(1)


# Functions

def get_base_url(protocol, host, port):
    """Get complete url of api"""

    return f"{protocol}://{host}:{port}"


def get_login_headers(user, password):
    basic_auth = f"{user}:{password}".encode()
    return {'Content-Type': 'application/json',
            'Authorization': f'Basic {b64encode(basic_auth).decode()}'}


def get_token_login_api(protocol, host, port, user, password, login_endpoint, timeout):
    """Get API login token"""

    login_url = f"{get_base_url(protocol, host, port)}{login_endpoint}"

    for _ in range(10):
        response = requests.get(login_url, headers=get_login_headers(user, password), verify=False, timeout=timeout)

        if response.status_code == 200:
            return json.loads(response.content.decode())['data']['token']
        time.sleep(1)
    else:
        raise RuntimeError(f"Error obtaining login token: {response.json()}")


def get_api_details_dict(protocol=API_PROTOCOL, host=API_HOST, port=API_PORT, user=API_USER, password=API_PASS,
                         login_endpoint=API_LOGIN_ENDPOINT, timeout=10):
    login_token = get_token_login_api(protocol, host, port, user, password, login_endpoint, timeout)
    """Get API details"""
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
        
    References: https://documentation.wazuh.com/current/user-manual/api/reference.html#operation/api.controllers.manager_controller.get_configuration

    Args:
        section (str): wazuh configuration section, E.g: "active-response", "ruleset"...
        field   (str): section child. E.g, fields for ruleset section are: decoder_dir, rule_dir, etc

    Returns:
        `obj`(str or map): active configuration indicated by Wazuh API. If section and field are selected, it will return a String,
        if not, it will return a map for the section/entire configurations with fields/sections as keys
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
    while attempts > 0:
        try:
            attempts -= 1
            get_token_login_api(protocol, host, port, user, password, login_endpoint, timeout)
        except requests.exceptions.ConnectionError:
            time.sleep(1)
        else:
            break