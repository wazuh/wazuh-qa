'''
brief: This module holds common methods and variables for the authd tests
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.
    Created by Wazuh, Inc. <info@wazuh.com>.
    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''

import re


DAEMON_NAME = 'wazuh-authd'
AUTHD_KEY_REQUEST_TIMEOUT = 10


def create_authd_request(input):
    """
    Creates a command to request keys to Authd.

    Args:
        input (dict): Dictionary with the content of the request command.
    """
    command = ""

    if 'password' in input:
        password = input['password']
        command = command + f'OSSEC PASS: {password} '

    command = command + 'OSSEC'

    if 'name' in input:
        name = input['name']
        command = command + f" A:'{name}'"
    else:
        raise Exception("Error creating the Authd command: 'name' is required")

    if 'group' in input:
        group = input['group']
        command = command + f" G:'{group}'"

    if 'ip' in input:
        ip = input['ip']
        command = command + f" IP:'{ip}'"

    if 'key_hash' in input:
        key_hash = input['key_hash']
        command = command + f" K:'{key_hash}'"

    return command


def validate_argument(received, expected, argument_name):
    if received != expected:
        return 'error', f"Invalid '{argument_name}': '{received}' received, '{expected}' expected."
    else:
        return 'success', ''


def validate_authd_response(response, expected):
    """
    Validates if the different items of an Authd response are as expected. Any item inexistent in expected won't
    be validated.

    Args:
        response (str): The Authd response to be validated.
        expected (dict): Dictionary with the items to validate.
    """
    response = response.split(sep=" ", maxsplit=1)
    status = response[0]
    result = 'success'
    err_msg = ''
    if expected['status'] == 'success':
        result, err_msg = validate_argument(status, 'OSSEC', 'status')
        if result != 'success':
            return result, err_msg

        agent_key = response[1].split('\'')[1::2][0].split()
        id = agent_key[0]
        name = agent_key[1]
        ip = agent_key[2]
        key = agent_key[3]

        if 'id' in expected:
            result, err_msg = validate_argument(id, expected['id'], 'id')
            if result != 'success':
                return result, err_msg

        if 'name' in expected:
            result, err_msg = validate_argument(name, expected['name'], 'name')
            if result != 'success':
                return result, err_msg

        if 'ip' in expected:
            result, err_msg = validate_argument(ip, expected['ip'], 'ip')
            if result != 'success':
                return result, err_msg

        if 'key' in expected:
            result, err_msg = validate_argument(key, expected['key'], 'key')
            if result != 'success':
                return result, err_msg

    elif expected['status'] == 'error':
        result, err_msg = validate_argument(status, 'ERROR:', 'status')
        if result != 'success':
            return result, err_msg

        message = response[1]
        if 'message' in expected:
            if re.match(expected['message'], message) is None:
                return 'error', f"Invalid 'message': '{message}' received, '{expected['message']}' expected"
    else:
        raise Exception('Invalid expected status')

    return result, err_msg
