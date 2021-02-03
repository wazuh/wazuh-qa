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

from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from conftest import *
from subprocess import Popen, PIPE, STDOUT

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.agent]

EXECD_SOCKET = os.path.join(WAZUH_PATH, 'queue', 'alerts', 'execq')
CRYPTO = "aes"
SERVER_ADDRESS = 'localhost'
PROTOCOL = "udp"

test_metadata = [
    {
        'command': 'firewall-drop15',
        'rule_id': '5715',
        'ip': '3.3.3.3',
        'results': {
            'success': True,
        }
    },
    {
        'command': 'firewall-drop0',
        'ip': '3.3.3.3',
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

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=test_metadata)

@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param

def validate_ar_message(message, x):
    if x == 0:
        command = 'add'
    else:
        command = 'delete'

    json_alert = json.loads(message) # Alert in JSON
    assert json_alert['command'], 'Missing command in JSON message'
    assert json_alert['command'] == command, 'Invalid command in JSON message'

def wait_message_line(line):
    if ("{\"version\"" in line):
        return line.split("/ossec/active-response/bin/firewall-drop: ", 1)[1]
    return None

def wait_invalid_input_message_line(line):
    if ("Cannot read 'srcip' from data" in line):
        return True
    return None

def build_message(metadata, expected):
    origin = "\"name\":\"\",\"module\":\"wazuh-analysisd\""
    rules = "\"level\":5,\"description\":\"Test.\",\"id\":" + metadata['rule_id']

    if expected['success'] == False:
        return "{\"version\":1,\"origin\":{" + origin + "},\"command\":\"" + metadata['command'] + "\",\"parameters\":{\"extra_args\":[],\"alert\":{\"rule\":{" + rules + "},\"data\":{\"dstuser\":\"Test.\"}}}}"

    return "{\"version\":1,\"origin\":{" + origin + "},    \"command\":\"" + metadata['command'] + "\",\"parameters\":{\"extra_args\":[],\"alert\":{\"rule\":{" + rules + "},\"data\":{\"dstuser\":\"Test.\", \"srcip\":\"" + metadata['ip'] + "\"}}}}"

def remove_ip_from_iptables(metadata):
    ar_log_monitor = FileMonitor(AR_LOG_FILE_PATH)
    param = "{\"version\":1,\"origin\":{\"name\":\"\",\"module\":\"wazuh-execd\"},\"command\":\"delete\",\"parameters\":{\"extra_args\":[],\"alert\":{\"data\":{\"srcip\":\"" + metadata['ip'] + "\",\"dstuser\":\"Test\"}},\"program\":\"/var/ossec/active-response/bin/firewall-drop\"}}"
    firewall_drop_script_path = os.path.join(WAZUH_PATH, 'active-response/bin', 'firewall-drop')

    iptables_file = os.popen('iptables -L')
    for iptables_line in iptables_file:
        if metadata['ip'] in iptables_line:
            p = Popen([firewall_drop_script_path], stdout=PIPE, stdin=PIPE, stderr=PIPE)
            p.stdin.write('{}\n\0'.format(param).encode('utf-8'))
            p.stdin.close()

    time.sleep(10)

    iptables_file = os.popen('iptables -L')
    for iptables_line in iptables_file:
        if metadata['ip']  in iptables_line:
            raise AssertionError("Unable to remove IP from iptables")

def test_execd_firewall_drop(set_debug_mode, set_ar_conf_mode, get_configuration, test_version, configure_environment, restart_service):
    metadata = get_configuration['metadata']
    expected = metadata['results']
    ossec_log_monitor = FileMonitor(LOG_FILE_PATH)
    ar_log_monitor = FileMonitor(AR_LOG_FILE_PATH)

    # Before starting the test we remove the IP from iptable if it exists
    remove_ip_from_iptables(metadata)
    clean_logs()

    message = build_message(metadata, expected)
    send_message(message, EXECD_SOCKET)

    ##### Checking AR in ossec logs ####
    try:
        ossec_log_monitor.start(timeout=10, callback=wait_received_message_line)
    except TimeoutError as err:
        raise AssertionError("Received message tooks too much!")

    ##### Checking AR in active-response logs ####
    try:
        ar_log_monitor.start(timeout=20, callback=wait_start_message_line)
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

            # Checking if the IP was added/removed in iptables
            iptables_file = os.popen('iptables -L')
            flag = False
            for iptables_line in iptables_file:
                if metadata['ip'] in iptables_line:
                    flag = True

            if flag == False and x == 0:
                raise AssertionError("IP was not added to iptable")
            elif flag == True and x == 1:
                raise AssertionError("IP was not removed to iptable")

            time.sleep(10)
    else:
        try:
            ar_log_monitor.start(timeout=10, callback=wait_invalid_input_message_line)
        except TimeoutError as err:
            raise AssertionError("Invalid input message tooks too much!")