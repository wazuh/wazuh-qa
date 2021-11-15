'''
brief: This module holds common methods and variables for the authd tests
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.
    Created by Wazuh, Inc. <info@wazuh.com>.
    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''

import re
import pytest
import time
from wazuh_testing.tools import CLIENT_KEYS_PATH, LOG_FILE_PATH
from wazuh_testing.wazuh_db import query_wdb
from wazuh_testing.tools.monitoring import FileMonitor, make_callback, AUTHD_DETECTOR_PREFIX
from wazuh_testing.tools.services import control_service, check_daemon_status
from wazuh_testing.tools.configuration import set_section_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools.file import truncate_file


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


# Functions
def validate_authd_logs(expected_logs, log_monitor=None):
    if not log_monitor:
        log_monitor = FileMonitor(LOG_FILE_PATH)

    for log in expected_logs:
        log_monitor.start(timeout=AUTHD_KEY_REQUEST_TIMEOUT,
                          callback=make_callback(log, prefix=AUTHD_DETECTOR_PREFIX,
                                                 escape=True),
                          error_message=f"Expected log does not occured: '{log}'")


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


def clean_agents_from_db():
    """
    Clean agents from DB
    """
    command = 'global sql DELETE FROM agent WHERE id != 0'
    try:
        query_wdb(command)
    except Exception:
        raise Exception('Unable to clean agents')


def insert_agent_in_db(id=1, name="TestAgent", ip="any", registration_time=0, connection_status=0,
                       disconnection_time=0):
    """
    Write agent in global.db
    """
    insert_command = f'global insert-agent {{"id":{id},"name":"{name}","ip":"{ip}","date_add":{registration_time}}}'
    update_command = f'global sql UPDATE agent SET connection_status = "{connection_status}",\
                       disconnection_time = "{disconnection_time}" WHERE id = {id};'
    try:
        query_wdb(insert_command)
        query_wdb(update_command)
    except Exception:
        raise Exception(f'Unable to add agent {id}')


@pytest.fixture(scope='function')
def insert_pre_existent_agents(get_current_test_case, stop_authd_function):
    agents = get_current_test_case.get('pre_existent_agents', [])
    time_now = int(time.time())
    try:
        keys_file = open(CLIENT_KEYS_PATH, 'w')
    except IOError as exception:
        raise exception

    clean_agents_from_db()

    for agent in agents:
        id = agent['id'] if 'id' in agent else '001'
        name = agent['name'] if 'name' in agent else f'TestAgent{id}'
        ip = agent['ip'] if 'ip' in agent else 'any'
        key = agent['key'] if 'key' in agent else 'TopSecret'
        connection_status = agent['connection_status'] if 'connection_status' in agent else 'never_connected'
        if 'disconnection_time' in agent and 'delta' in agent['disconnection_time']:
            disconnection_time = time_now + agent['disconnection_time']['delta']
        elif 'disconnection_time' in agent and 'value' in agent['disconnection_time']:
            disconnection_time = agent['disconnection_time']['value']
        else:
            disconnection_time = time_now
        if 'registration_time' in agent and 'delta' in agent['registration_time']:
            registration_time = time_now + agent['registration_time']['delta']
        elif 'registration_time' in agent and 'value' in agent['registration_time']:
            registration_time = agent['registration_time']['value']
        else:
            registration_time = time_now

        # Write agent in client.keys
        keys_file.write(f'{id} {name} {ip} {key}\n')

        # Write agent in global.db
        insert_agent_in_db(id, name, ip, registration_time, connection_status, disconnection_time)

    keys_file.close()

def callback_agentd_startup(line):
        if 'Accepting connections on port 1515' in line:
            return line
        return None

def override_wazuh_conf(configuration):
    # Stop Wazuh
    control_service('stop', daemon='wazuh-authd')
    check_daemon_status(running_condition=False, target_daemon='wazuh-authd')
    truncate_file(LOG_FILE_PATH)

    # Configuration for testing
    test_config = set_section_wazuh_conf(configuration.get('sections'))
    # Set new configuration
    write_wazuh_conf(test_config)
    # Start Wazuh daemons
    control_service('start', daemon='wazuh-authd', debug_mode=True)

    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=AUTHD_KEY_REQUEST_TIMEOUT, callback=callback_agentd_startup)