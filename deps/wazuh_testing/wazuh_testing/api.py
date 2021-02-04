# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
from base64 import b64encode
import requests
import json

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
    response = requests.get(login_url, headers=get_login_headers(user, password), verify=False, timeout=timeout)

    if response.status_code == 200:
        return json.loads(response.content.decode())['data']['token']
    else:
        raise Exception(f"Error obtaining login token: {response.json()}")


def get_api_details_dict(protocol=API_PROTOCOL, host=API_HOST, port=API_PORT, user=API_USER, password=API_PASS,
                         login_endpoint=API_LOGIN_ENDPOINT, timeout=10):
    """Get API details"""
    return {
        'base_url': get_base_url(protocol, host, port),
        'auth_headers': {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {get_token_login_api(protocol, host, port, user, password, login_endpoint, timeout)}'
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
