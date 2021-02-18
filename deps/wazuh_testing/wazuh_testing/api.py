# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import re
import time
from base64 import b64encode

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

    response = None
    for _ in range(10):
        response = requests.get(login_url, headers=get_login_headers(user, password), verify=False, timeout=timeout)

        if response.status_code == 200:
            return json.loads(response.content.decode())['data']['token']
        time.sleep(1)

    raise Exception(f"Error obtaining login token: {response.json()}")


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


def get_manager_configuration(section=None, field=None):
    """
        Get Wazuh manager configuration response from API using GET /manager/configuration
        https://documentation.wazuh.com/current/user-manual/api/reference.html#operation/api.controllers.manager_controller.get_configuration

        Args:
        section (str): Indicates the wazuh configuration section, for example: "active-response", "alerts"...
        field   (str): Indicate a section child. E.g, fields for ruleset section are: decoder_dir, rule_dir, etc

        Returns:
            active configuration indicated by Wazuh API. If section and field are selected, it will return a String,
            if not, it will return a map for the section/entire configurations with fields/sections as keys
    """
    api_details = get_api_details_dict()
    api_query = f"{api_details['base_url']}/manager/configuration?"

    if section is not None:
        api_query += f"section={section}"
        if field is not None:
            api_query += f"&field={field}"

    response = requests.get(api_query, headers=api_details['auth_headers'], verify=False)

    try:
        assert response.json()['error'] == 0, f"Wazuh API response status different from 0: {response.json()}"
        answer = response.json()['data']['affected_items'][0]

        if section is not None:
            answer = answer[section]
            if isinstance(answer, list) and len(answer) == 1:
                answer = answer[0]
            if field is not None:
                answer = answer[field]
        return answer

    except KeyError:
        raise Exception(f"Wazuh API request failed: {response.json()}")
