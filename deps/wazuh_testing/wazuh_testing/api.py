# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
from base64 import b64encode
import requests
import json

# Variables

api_protocol = 'https'
api_host = 'localhost'
api_port = '55000'
api_user = 'wazuh'
api_password = 'wazuh'
api_version = 'v4'
api_login_endpoint = '/security/user/authenticate'


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

def get_base_url(protocol, host, port, version):
    """Get complete url of api"""
    if not protocol:
        protocol = api_protocol
    if not host:
        host = api_host
    if not port:
        port = api_port
    if not version:
        version = api_version

    return f"{protocol}://{host}:{port}/{version}"


def get_login_headers(user, password):
    basic_auth = f"{user}:{password}".encode()
    return {'Content-Type': 'application/json',
                     'Authorization': f'Basic {b64encode(basic_auth).decode()}'}


def get_token_login_api(protocol, host, port, version, user, password, login_endpoint, timeout):
    """Get API login token"""

    if not protocol:
        protocol = api_protocol
    if not host:
        host = api_host
    if not port:
        port = api_port
    if not version:
        version = api_version
    if not user:
        user = api_user
    if not password:
        password = api_password
    if not login_endpoint:
        login_endpoint = api_login_endpoint

    login_url = f"{get_base_url(protocol, host, port, version)}{login_endpoint}"
    response = requests.get(login_url, headers=get_login_headers(user, password), verify=False, timeout=timeout)

    if response.status_code == 200:
        return json.loads(response.content.decode())['token']
    else:
        raise Exception(f"Error obtaining login token: {response.json()}")