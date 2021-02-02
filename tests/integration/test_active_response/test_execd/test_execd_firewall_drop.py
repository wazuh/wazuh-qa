# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import hashlib
import os
import platform
import pytest
import time
import requests
import subprocess
import yaml
import json
import socket

from configobj import ConfigObj
from datetime import datetime
from wazuh_testing.tools import WAZUH_PATH, WAZUH_SOCKETS, LOG_FILE_PATH
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.monitoring import FileMonitor


pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.agent]

AR_LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs/active-responses.log')
EXECD_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'alerts', 'execq')
CRYPTO = "aes"
SERVER_ADDRESS = 'localhost'
PROTOCOL = "udp"

def get_current_version():
    if platform.system() == 'Linux':
        config_file_path = os.path.join(WAZUH_PATH, 'etc', 'ossec-init.conf')
        _config = ConfigObj(config_file_path)
        return _config['VERSION']

    else:
        version = None
        with open(os.path.join(WAZUH_PATH, 'VERSION'), 'r') as f:
            version = f.read()
            version = version[:version.rfind('\n')]
        return version


_agent_version = get_current_version()

test_metadata = [
    {
        'command': 'firewall-drop15',
        'rule_id': '5715',
        'ip': '5.5.5.5',
        'results': {
            'success': True,
        }
    },
    {
        'command': 'firewall-drop0',
        'rule_id': '5715',
        'results': {
            'success': False,
        }
    },
]

params = [
    {
        'CRYPTO': CRYPTO,
        'SERVER_ADDRESS': SERVER_ADDRESS,
        'REMOTED_PORT': 1514,
        'PROTOCOL': PROTOCOL
    } for _ in range(0, len(test_metadata))
]


def load_tests(path):
    """ Loads a yaml file from a path
    Return
    ----------
    yaml structure
    """
    with open(path) as f:
        return yaml.safe_load(f)

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=test_metadata)

@pytest.fixture(scope="session")
def set_ar_conf_mode():
    local_int_conf_path = os.path.join(WAZUH_PATH, 'etc/shared', 'ar.conf')
    debug_line = 'firewall-drop15 - firewall-drop - 15\n'
    with open(local_int_conf_path, 'w') as local_file_write:
        local_file_write.write('\n'+debug_line)
    with open(local_int_conf_path, 'r') as local_file_read:
        lines = local_file_read.readlines()
        for line in lines:
            if line == debug_line:
                return

@pytest.fixture(scope="session")
def set_debug_mode():
    local_int_conf_path = os.path.join(WAZUH_PATH, 'etc', 'local_internal_options.conf')
    debug_line = 'execd.debug=2\n'
    with open(local_int_conf_path, 'r') as local_file_read:
        lines = local_file_read.readlines()
        for line in lines:
            if line == debug_line:
                return
    with open(local_int_conf_path, 'a') as local_file_write:
        local_file_write.write('\n'+debug_line)

@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param

@pytest.fixture(scope="session")
def set_debug_mode():
    local_int_conf_path = os.path.join(WAZUH_PATH, 'etc', 'local_internal_options.conf')
    debug_line = 'execd.debug=2\n'
    with open(local_int_conf_path, 'r') as local_file_read:
        lines = local_file_read.readlines()
        for line in lines:
            if line == debug_line:
                return
    with open(local_int_conf_path, 'a') as local_file_write:
        local_file_write.write('\n'+debug_line)

def validate_ar_message(message, x):
    if x == 0:
        command = 'add'
    else:
        command = 'delete'

    json_alert = json.loads(message) # Alert in JSON
    assert json_alert['command'], 'Missing command in JSON message'
    assert json_alert['command'] == command, 'Invalid command in JSON message'

def send_message(data_object, socket_path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect(socket_path)
    sock.send(data_object.encode())
    sock.close()

def wait_received_message_line(line):
    if ("DEBUG: Received message: " in line):
        return True
    return None

def wait_start_message_line(line):
    if ("Starting" in line):
        return True
    return None

def wait_message_line(line):
    if ("{\"version\"" in line):
        return line.split("/ossec/active-response/bin/firewall-drop: ", 1)[1]
    return None

def wait_invalid_input_message_line(line):
    if ("Cannot read 'srcip' from data" in line):
        return True
    return None

def wait_ended_message_line(line):
    if ("Ended" in line):
        return True
    return None

def build_message(metadata, expected):
    origin = "\"name\":\"\",\"module\":\"wazuh-analysisd\""
    command = "\"" + metadata['command'] + "\""
    rules = "\"level\":5,\"description\":\"Test.\",\"id\":" + metadata['rule_id']

    if expected['success'] == False:
        return "{\"version\":1,\"origin\":{" + origin + "},\"command\":" + command + ",\"parameters\":{\"extra_args\":[],\"alert\":{\"timestamp\":\"2021-01-27T19:39:22.918+0000\",\"rule\":{" + rules + "},\"data\":{\"dstuser\":\"Test.\"},\"id\":\"1611776362.714178\"}}}"

    return "{\"version\":1,\"origin\":{" + origin + "},\"command\":" + command + ",\"parameters\":{\"extra_args\":[],\"alert\":{\"timestamp\":\"2021-01-27T19:39:22.918+0000\",\"rule\":{" + rules + "},\"data\":{\"dstuser\":\"Test.\", \"srcip\":\"" + metadata['ip'] + "\"},\"id\":\"1611776362.714178\"}}}"

def clean_logs():
    truncate_file(LOG_FILE_PATH)
    truncate_file(AR_LOG_FILE_PATH)

@pytest.fixture(scope="session")
def test_version():
    if _agent_version < "v4.2.0":
        raise AssertionError("The version of the agent is < 4.2.0")

@pytest.fixture(scope="function")
def restart_service():
    clean_logs()
    control_service('restart')
    yield

def test_1(set_debug_mode, set_ar_conf_mode, get_configuration, test_version, configure_environment, restart_service):
    metadata = get_configuration['metadata']
    expected = metadata['results']
    ossec_log_monitor = FileMonitor(LOG_FILE_PATH)
    ar_log_monitor = FileMonitor(AR_LOG_FILE_PATH)

    message = build_message(metadata, expected)
    send_message(message, EXECD_SOCKET)

    ##### Checking AR in ossec logs ####
    try:
        ossec_log_monitor.start(timeout=10, callback=wait_received_message_line)
    except TimeoutError as err:
        raise AssertionError("Received message tooks too much!")

    ##### Checking AR in active-response logs ####
    try:
        ar_log_monitor.start(timeout=10, callback=wait_start_message_line)
    except TimeoutError as err:
        raise AssertionError("Start message tooks too much!")

    if expected['success'] == True:
        for x in range(2):
            try:
                ar_log_monitor.start(timeout=10, callback=wait_message_line)
            except TimeoutError as err:
                raise AssertionError("AR message tooks too much!")

            last_log = ar_log_monitor.result()
            validate_ar_message(last_log, x)

            try:
                ar_log_monitor.start(timeout=10, callback=wait_ended_message_line)
            except TimeoutError as err:
                raise AssertionError("Ended message tooks too much!")

            time.sleep(5)

            mystring = os.popen('iptables -L')
            flag = False
            for process in mystring:
                print(process)
                if metadata['ip'] in process:
                    flag = True

            if flag == False and x == 0:
                raise AssertionError("IP was not added to iptable")
            elif flag == True and x == 1:
                raise AssertionError("IP was not deleted to iptable")
    else:
        try:
            ar_log_monitor.start(timeout=10, callback=wait_invalid_input_message_line)
        except TimeoutError as err:
            raise AssertionError("Invalid input message tooks too much!")



