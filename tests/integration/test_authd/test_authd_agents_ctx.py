# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import subprocess
import time

import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status

CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

def load_tests(path):
    """ Loads a yaml file from a path
    Return
    ----------
    yaml structure
    """
    with open(path) as f:
        return yaml.safe_load(f)


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=None, metadata=None)

# Variables
log_monitor_paths = []

ls_sock_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'auth'))
receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2'), (ls_sock_path, 'AF_UNIX', 'TCP')]

monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


# Aux
@pytest.fixture(scope="function")
def set_up_groups(request):
    subprocess.call(['/var/ossec/bin/agent_groups', '-a', '-g', 'TestGroup', '-q'])
    yield
    subprocess.call(['/var/ossec/bin/agent_groups', '-r', '-g', 'TestGroup', '-q'])


@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


def clean_agents_ctx():
    clean_keys()
    clean_groups()
    clean_rids()
    clean_agents_timestamp()
    clean_diff()


def wait_server_connection():
    """Wait until agentd has begun"""

    def callback_agentd_startup(line):
        if 'Accepting connections on port 1515' in line:
            return line
        return None

    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=30, callback=callback_agentd_startup)


def clean_logs():
    truncate_file(LOG_FILE_PATH)


def clean_keys():
    truncate_file(CLIENT_KEYS_PATH)


def clean_groups():
    groups_folder = os.path.join(WAZUH_PATH, 'queue', 'agent-groups')
    for filename in os.listdir(groups_folder):
        file_path = os.path.join(groups_folder, filename)
        try:
            os.unlink(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))


def clean_diff():
    diff_folder = os.path.join(WAZUH_PATH, 'queue', 'diff')
    for agent_diff in os.listdir(diff_folder):
        diff_path = os.path.join(diff_folder, agent_diff)
        try:
            shutil.rmtree(diff_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (diff_path, e))


def clean_rids():
    rids_folder = os.path.join(WAZUH_PATH, 'queue', 'rids')
    for filename in os.listdir(rids_folder):
        file_path = os.path.join(rids_folder, filename)
        if "sender_counter" not in file_path:
            try:
                os.unlink(file_path)
            except Exception as e:
                print('Failed to delete %s. Reason: %s' % (file_path, e))


def clean_agents_timestamp():
    timestamp_path = os.path.join(WAZUH_PATH, 'queue', 'agents-timestamp')
    truncate_file(timestamp_path)


def check_agent_groups(id, expected, timeout=30):
    group_path = os.path.join(WAZUH_PATH, 'queue', 'agent-groups', id)
    wait = time.time() + timeout
    while time.time() < wait:
        ret = os.path.exists(group_path)
        if ret == expected:
            return True
    return False


def check_diff(name, expected, timeout=30):
    diff_path = os.path.join(WAZUH_PATH, 'queue', 'diff', name)
    wait = time.time() + timeout
    while time.time() < wait:
        ret = os.path.exists(diff_path)
        if ret == expected:
            return True
    return False


def check_client_keys(id, expected):
    found = False
    try:
        with open(CLIENT_KEYS_PATH) as client_file:
            client_lines = client_file.read().splitlines()
            for line in client_lines:
                data = line.split(" ")
                if data[0] == id:
                    found = True
                    break
    except IOError:
        raise

    if found == expected:
        return True
    else:
        return False


def check_agent_timestamp(id, name, ip, expected):
    timestamp_path = os.path.join(WAZUH_PATH, 'queue', 'agents-timestamp')
    line = "{} {} {}".format(id, name, ip)
    found = False
    try:
        with open(timestamp_path) as file:
            file_lines = file.read().splitlines()
            for file_line in file_lines:
                if line in file_line:
                    found = True
                    break
    except IOError:
        raise

    if found == expected:
        return True
    else:
        return False


def check_rids(id, expected):
    agent_info_path = os.path.join(WAZUH_PATH, 'queue', 'rids', id)
    if expected == os.path.exists(agent_info_path):
        return True
    else:
        return False


def create_rids(id):
    rids_path = os.path.join(WAZUH_PATH, 'queue', 'rids', id)
    try:
        file = open(rids_path, 'w')
        file.close()
        os.chmod(rids_path, 0o777)
    except IOError:
        raise


def create_diff(name):
    SIGID = '533'
    diff_folder = os.path.join(WAZUH_PATH, 'queue', 'diff', name)
    try:
        os.mkdir(diff_folder)
    except IOError:
        raise

    sigid_folder = os.path.join(diff_folder, SIGID)
    try:
        os.mkdir(sigid_folder)
    except IOError:
        raise

    last_entry_path = os.path.join(sigid_folder, 'last-entry')
    try:
        file = open(last_entry_path, 'w')
        file.close()
        os.chmod(last_entry_path, 0o777)
    except IOError:
        raise


def register_agent_main_server(Name, Group=None, IP=None):
    message = "OSSEC A:'{}'".format(Name)
    if Group:
        message += " G:'{}'".format(Group)
    if IP:
        message += " IP:'{}'".format(IP)

    receiver_sockets[0].open()
    receiver_sockets[0].send(message, size=False)
    timeout = time.time() + 10
    response = ''
    while response == '':
        response = receiver_sockets[0].receive().decode()
        if time.time() > timeout:
            raise ConnectionResetError('Manager did not respond to sent message!')
    time.sleep(5)
    return response


def register_agent_local_server(Name, Group=None, IP=None):
    message = '{{"arguments":{{"force":0,"name":"{}"'.format(Name)
    if Group:
        message += ',"groups":"{}"'.format(Group)
    if IP:
        message += ',"ip":"{}"'.format(IP)
    else:
        message += ',"ip":"any"'
    message += '},"function":"add"}'

    receiver_sockets[1].open()
    receiver_sockets[1].send(message, size=True)
    response = receiver_sockets[1].receive(size=True).decode()
    time.sleep(5)
    return response


# Tests
def duplicate_ip_agent_delete_test(server):
    """Register a first agent, then register an agent with duplicated IP.
        Check that client.keys, agent-groups, agent-timestamp and agent diff were updated correctly

    Parameters
    ----------
    server : registration server to create registrations
        Valid values : "main", "local"
    """
    if server == "main":
        SUCCESS_RESPONSE = "OSSEC K:'"
        register_agent = register_agent_main_server
    elif server == "local":
        SUCCESS_RESPONSE = '{"error":0,'
        register_agent = register_agent_local_server
    else:
        raise Exception('Invalid registration server')

    # Register first agent
    response = register_agent('userA', 'TestGroup', '192.0.0.0')
    create_rids('001')  # Simulate rids was created
    create_diff('userA')  # Simulate diff folder was created
    assert response[:len(SUCCESS_RESPONSE)] == SUCCESS_RESPONSE, 'Wrong response received'
    assert check_client_keys('001', True), 'Agent key was never created'
    assert check_agent_groups('001', True), 'Agent group was never created'
    assert check_agent_timestamp('001', 'userA', '192.0.0.0', True), 'Agent_timestamp was never created'
    assert check_rids('001', True), 'Rids file was never created'
    assert check_diff('userA', True), 'Agent diff folder was never created'

    # Register agent with duplicate IP
    response = register_agent('userC', 'TestGroup', '192.0.0.0')
    assert response[:len(SUCCESS_RESPONSE)] == SUCCESS_RESPONSE, 'Wrong response received'
    assert check_client_keys('002', True), 'Agent key was never created'
    assert check_client_keys('001', False), 'Agent key was not removed'
    assert check_agent_groups('002', True), 'Agent group was never created'
    assert check_agent_groups('001', False), 'Agent group was not removed'
    assert check_agent_timestamp('002', 'userC', '192.0.0.0', True), 'Agent_timestamp was never created'
    assert check_agent_timestamp('001', 'userA', '192.0.0.0', False), 'Agent_timestamp was not removed'
    assert check_rids('001', False), 'Rids file was was not removed'
    assert check_diff('userA', False), 'Agent diff folder was not removed'


def duplicate_name_agent_delete_test(server):
    """Register a first agent, then register an agent with duplicated Name.
        Check that client.keys, agent-groups, agent-timestamp and agent diff were updated correctly

    Parameters
    ----------
    server : registration server to create registrations
        Valid values : "main", "local"
    """
    if server == "main":
        SUCCESS_RESPONSE = "OSSEC K:'"
        register_agent = register_agent_main_server
    elif server == "local":
        SUCCESS_RESPONSE = '{"error":0,'
        register_agent = register_agent_local_server
    else:
        raise Exception('Invalid registration server')

    # Register first agents
    response = register_agent('userB', 'TestGroup')
    create_rids('003')  # Simulate rids was created
    create_diff('userB')  # Simulate diff folder was created
    assert response[:len(SUCCESS_RESPONSE)] == SUCCESS_RESPONSE, 'Wrong response received'
    assert check_client_keys('003', True), 'Agent key was never created'
    assert check_agent_groups('003', True), 'Agent group was never created'
    assert check_agent_timestamp('003', 'userB', 'any', True), 'Agent_timestamp was never created'
    assert check_rids('003', True), 'Rids file was never created'
    assert check_diff('userB', True), 'Agent diff folder was never created'

    # Register agent with duplicate Name
    response = register_agent('userB', 'TestGroup')
    assert response[:len(SUCCESS_RESPONSE)] == SUCCESS_RESPONSE, 'Wrong response received'
    assert check_client_keys('004', True), 'Agent key was never created'
    assert check_client_keys('003', False), 'Agent key was not removed'
    assert check_agent_groups('004', True), 'Agent group was never created'
    assert check_agent_groups('003', False), 'Agent group was not removed'
    assert check_agent_timestamp('004', 'userB', 'any', True), 'Agent_timestamp was never created'
    assert check_agent_timestamp('003', 'userB', 'any', False), 'Agent_timestamp was not removed'
    assert check_rids('003', False), 'Rids file was was not removed'
    assert check_diff('userB', False), 'Agent diff folder was not removed'


def test_ossec_authd_agents_ctx_main(get_configuration, set_up_groups, configure_environment,
                                     configure_sockets_environment, connect_to_sockets_module):
    control_service('stop', daemon='wazuh-authd')
    check_daemon_status(running=False, daemon='wazuh-authd')
    time.sleep(1)
    clean_logs()
    clean_agents_ctx()
    time.sleep(1)
    control_service('start', daemon='wazuh-authd')
    check_daemon_status(running=True, daemon='wazuh-authd')
    wait_server_connection()
    time.sleep(1)

    duplicate_ip_agent_delete_test("main")
    duplicate_name_agent_delete_test("main")

    clean_agents_ctx()


def test_ossec_authd_agents_ctx_local(get_configuration, set_up_groups, configure_environment,
                                      configure_sockets_environment, connect_to_sockets_module):
    control_service('stop', daemon='wazuh-authd')
    check_daemon_status(running=False, daemon='wazuh-authd')
    time.sleep(1)
    clean_logs()
    clean_agents_ctx()
    time.sleep(1)
    control_service('start', daemon='wazuh-authd')
    check_daemon_status(running=True, daemon='wazuh-authd')
    wait_server_connection()
    time.sleep(1)

    duplicate_ip_agent_delete_test("local")
    duplicate_name_agent_delete_test("local")

    clean_agents_ctx()
