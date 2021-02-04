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
import psutil

from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from conftest import *

pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

CONF_FOLDER = '' if platform.system() == 'Windows' else 'etc'
CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, CONF_FOLDER, 'client.keys')
SERVER_KEY_PATH = os.path.join(WAZUH_PATH, CONF_FOLDER, 'manager.key')
SERVER_CERT_PATH = os.path.join(WAZUH_PATH, CONF_FOLDER, 'manager.cert')
CRYPTO = "aes"
SERVER_ADDRESS = 'localhost'
PROTOCOL = "tcp"

test_metadata = [
    {
        'command': 'restart-wazuh0',
        'rule_id': '554',
        'results': {
            'success': True,
        }
    },
    {
        'command': 'restart-wazuh0',
        'rule_id': '554',
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

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=test_metadata)

remoted_simulator = None

@pytest.fixture(scope="function")
def start_agent(request, get_configuration):
    metadata = get_configuration['metadata']
    authd_simulator = AuthdSimulator(server_address=SERVER_ADDRESS,
                                     enrollment_port=1515,
                                     key_path=SERVER_KEY_PATH,
                                     cert_path=SERVER_CERT_PATH)
    authd_simulator.start()
    global remoted_simulator
    remoted_simulator = RemotedSimulator(server_address=SERVER_ADDRESS,
                                         remoted_port=1514,
                                         protocol=PROTOCOL,
                                         mode='CONTROLED_ACK',
                                         start_on_init=True,
                                         client_keys=CLIENT_KEYS_PATH)

    remoted_simulator.setActiveResponseMessage(build_message(metadata, metadata['results']))

    # Clean client.keys file
    truncate_file(CLIENT_KEYS_PATH)
    time.sleep(1)

    control_service('stop')
    agent_auth_pat = 'bin' if platform.system() == 'Linux' else ''
    subprocess.call([f'{WAZUH_PATH}/{agent_auth_pat}/agent-auth', '-m',
                    SERVER_ADDRESS])
    control_service('start')

    yield

    remoted_simulator.stop()
    authd_simulator.shutdown()

@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param

def wait_message_line(line):
    if platform.system() == 'Windows' and "active-response/bin/restart-wazuh.exe: {\"version\"" in line:
        return True
    elif ("ossec/active-response/bin/restart-wazuh: {\"version\"" in line):
        return True
    return None

def wait_invalid_input_message_line(line):
    if ("Invalid input format" in line):
        return line
    return None

def wait_shutdown_message_line(line):
    if ("Shutdown received. Deleting responses." in line):
        return True
    return None

def build_message(metadata, expected):
    origin = "\"name\":\"\",\"module\":\"wazuh-analysisd\""
    rules = "\"level\":5,\"description\":\"Test.\",\"id\":" + metadata['rule_id']

    if expected['success'] == False:
        return "{\"origin\":{" + origin + "},\"command\":\"" + metadata['command'] + "\",\"parameters\":{\"extra_args\":[],\"alert\":{\"rule\":{" + rules + "}}}}"

    return "{\"version\":1,\"origin\":{" + origin + "},\"command\":\"" + metadata['command'] + "\",\"parameters\":{\"extra_args\":[],\"alert\":{\"rule\":{" + rules + "}}}}"

def test_execd_restart(set_debug_mode, get_configuration, test_version, configure_environment, start_agent, set_ar_conf_mode):
    metadata = get_configuration['metadata']
    expected = metadata['results']
    ossec_log_monitor = FileMonitor(LOG_FILE_PATH)
    ar_log_monitor = FileMonitor(AR_LOG_FILE_PATH)

    ##### Checking AR in ossec logs ####
    try:
        ossec_log_monitor.start(timeout=60, callback=wait_received_message_line)
    except TimeoutError as err:
        raise AssertionError("Received message tooks too much!")

    ##### Checking AR in active-response logs ####
    try:
        ar_log_monitor.start(timeout=60, callback=wait_start_message_line)
    except TimeoutError as err:
        raise AssertionError("Start message tooks too much!")

    if expected['success'] == True:
        try:
            ar_log_monitor.start(timeout=60, callback=wait_message_line)
        except TimeoutError as err:
            raise AssertionError("AR message tooks too much!")

        # Checking shutdown message in ossec logs
        try:
            ossec_log_monitor.start(timeout=60, callback=wait_shutdown_message_line)
        except TimeoutError as err:
            raise AssertionError("Shutdown message tooks too much!")

        # Checking if the restart-wazuh process is running
        flag = False
        for proc in psutil.process_iter():
            if 'restart-wazuh' in proc.name():
                flag = True

        if flag == False:
            raise AssertionError("The script is not running")

        try:
            ar_log_monitor.start(timeout=60, callback=wait_ended_message_line)
        except TimeoutError as err:
            raise AssertionError("Ended message tooks too much!")

    else:
        try:
            ar_log_monitor.start(timeout=60, callback=wait_invalid_input_message_line)
        except TimeoutError as err:
            raise AssertionError("Invalid input message tooks too much!")
