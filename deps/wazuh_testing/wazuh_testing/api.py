# Copyright (C) 2015-2020, Wazuh Inc.
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
        return json.loads(response.content.decode())['token']
    else:
        raise Exception(f"Error obtaining login token: {response.json()}")
