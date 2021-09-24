'''
brief: This module holds common methods and variables for the authd tests
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.
    Created by Wazuh, Inc. <info@wazuh.com>.
    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''

import re


DAEMON_NAME = 'wazuh-authd'


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
    if expected['status'] == 'success':
        assert status == 'OSSEC', 'Invalid status response'
        agent_key = response[1].split('\'')[1::2][0].split()
        id = agent_key[0]
        name = agent_key[1]
        ip = agent_key [2]
        key = agent_key[3]
        if 'id' in expected:
            assert id == expected['id'], f'Invalid id response \'{id}\' '
        if 'name' in expected:
            assert name == expected['name'], f'Invalid name response \'{name}\''
        if 'ip' in expected:
            assert ip == expected['ip'], f'Invalid ip response\'{ip}\''
        if 'key' in expected:
            assert key == expected['key'], f'Invalid key response \'{key}\' '

    elif expected['status'] == 'error':
        assert status == "ERROR:"
        message = response[1]
        if 'message' in expected:
            assert re.match(expected['message'], message), f'Invalid error message response \'{message}\''

    else:
        raise Exception('Invalid expected status')
