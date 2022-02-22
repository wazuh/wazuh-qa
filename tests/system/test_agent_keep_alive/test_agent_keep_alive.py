'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: Wazuh agents sends keep alives to the manager with information that will be inserted in the global.db. Then,
       the manager will answer with an ACK.
tier: 0
modules:
    - remote
components:
    - manager
    - agent
daemons:
    - wazuh-remoted
os_platform:
    - linux
os_version:
    - Debian Buster
tags:
    - remoted
'''

import os
from time import sleep

import pytest

from wazuh_testing.tools import GLOBAL_DB_PATH, WAZUH_LOGS_PATH, WAZUH_PATH
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.tools.monitoring import FileMonitor, HostMonitor
from wazuh_testing.tools.system import HostManager
from wazuh_testing.remote import callback_ack, callback_inserting_keep_alive, callback_keep_alive_agent_ip, \
                                 callback_keep_alive_merged, callback_reading_keep_alive, callback_sending_keep_alive

# Hosts
testinfra_hosts = ["wazuh-manager", "wazuh-agent1"]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'provisioning', 'basic_environment', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = os.path.join(local_path, 'data/messages.yml')
tmp_path = os.path.join(local_path, 'tmp')
agent_conf_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..',
                               'provisioning', 'basic_environment', 'roles', 'agent-role', 'files', 'ossec.conf')
manager_conf_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data/config.yml')
test_cases_yaml = read_yaml(os.path.join(local_path, 'data/test_agent_keep_alive_cases.yml'))

wait_agent_start = 70
network = {}


def get_agent_keep_alive():
    for file in os.listdir(tmp_path):
        if file == 'wazuh-agent1_ossec.log.tmp':
            log_monitor = FileMonitor(os.path.join(tmp_path, file))
            log_monitor.start(timeout=30, callback=callback_sending_keep_alive)
            log_monitor.start(timeout=30, callback=callback_sending_merged)
            log_monitor.start(timeout=30, callback=callback_sending_agent_ip)


def get_manager_received_keep_alive():
    for file in os.listdir(tmp_path):
        if file == 'wazuh-manager_ossec.log.tmp':
            log_monitor = FileMonitor(os.path.join(tmp_path, file))
            log_monitor.start(timeout=30, callback=callback_reading_keep_alive)
            log_monitor.start(timeout=30, callback=callback_reading_merged)
            log_monitor.start(timeout=30, callback=callback_reading_agent_ip)
            log_monitor.start(timeout=30, callback=callback_inserting_keep_alive)
            log_monitor.start(timeout=30, callback=callback_inserting_merged)
            log_monitor.start(timeout=30, callback=callback_inserting_agent_ip)


# Remove the agent once the test has finished
@pytest.fixture(scope='function')
def clean_environment():
    yield
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="stopped")
    agent_id = host_manager.run_command('wazuh-manager', f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys')
    host_manager.get_host('wazuh-manager').ansible("command", f'{WAZUH_PATH}/bin/manage_agents -r {agent_id}',
                                                   check=False)
    host_manager.clear_file(host='wazuh-manager', file_path=os.path.join(WAZUH_PATH, 'etc', 'client.keys'))
    host_manager.clear_file(host='wazuh-agent1', file_path=os.path.join(WAZUH_PATH, 'etc', 'client.keys'))

    HostMonitor(inventory_path=inventory_path,
                messages_path=messages_path,
                tmp_path=tmp_path).clean_tmp_files()


@pytest.fixture(scope='function')
def enrollment():
    # Start the agent enrollment process by restarting the wazuh-agent
    host_manager.control_service(host='wazuh-manager', service='wazuh', state="restarted")
    host_manager.get_host('wazuh-agent1').ansible('command', 'service wazuh-agent restart', check=False)

    # Get agent's client.keys
    agent_client_keys = host_manager.get_file_content('wazuh-agent1', os.path.join(WAZUH_PATH, 'etc',
                                                      'client.keys')).split()
    key = agent_client_keys[3]

    yield key


@pytest.fixture(scope='module')
def get_ip_directions():
    global network

    manager_network = host_manager.get_host_ip('wazuh-manager', 'eth0')
    agent_network = host_manager.get_host_ip('wazuh-agent1', 'eth0')

    network['manager_network'] = manager_network
    network['agent_network'] = agent_network


@pytest.fixture(scope='function')
def configure_network(test_case):

    for configuration in test_case['test_case']:
        # Manager network configuration
        if 'ipv6' in configuration['manager_network']:
            host_manager.run_command('wazuh-manager', 'ip -4 addr flush dev eth0')
        elif 'ipv4' in configuration['manager_network']:
            host_manager.run_command('wazuh-manager', 'ip -6 addr flush dev eth0')

        # Agent network configuration
        if 'ipv6' in configuration['agent_network']:
            host_manager.run_command('wazuh-agent1', 'ip -4 addr flush dev eth0')

        elif 'ipv4' in configuration['agent_network']:
            host_manager.run_command('wazuh-agent1', 'ip -6 addr flush dev eth0')

    yield

    for configuration in test_case['test_case']:
        # Restore manager network configuration
        if 'ipv6' in configuration['manager_network']:
            host_manager.run_command('wazuh-manager', f"ip addr add {network['manager_network'][0]} dev eth0")
            host_manager.run_command('wazuh-manager', 'ip route add 172.24.27.0/24 via 0.0.0.0 dev eth0')
        elif 'ipv4' in configuration['manager_network']:
            host_manager.run_command('wazuh-manager', f"ip addr add {network['manager_network'][1]} dev eth0")
            host_manager.run_command('wazuh-manager', f"ip addr add {network['manager_network'][2]} dev eth0")

        # Restore agent network configuration
        if 'ipv6' in configuration['agent_network']:
            host_manager.run_command('wazuh-agent1', f"ip addr add {network['agent_network'][0]} dev eth0")
            host_manager.run_command('wazuh-agent1', 'ip route add 172.24.27.0/24 via 0.0.0.0 dev eth0')
        elif 'ipv4' in configuration['agent_network']:
            host_manager.run_command('wazuh-agent1', f"ip addr add {network['agent_network'][1]} dev eth0")
            host_manager.run_command('wazuh-agent1', f"ip addr add {network['agent_network'][2]} dev eth0")


@pytest.fixture(scope='function')
def modify_ip_address_conf(test_case):

    with open(agent_conf_file, 'r') as file:
        old_agent_configuration = file.read()

    with open(manager_conf_file, 'r') as file:
        old_manager_configuration = file.read()

    for configuration in test_case['test_case']:
        if 'yes' in configuration['ipv6_enabled']:
            new_manager_configuration = old_manager_configuration.replace('IPV6_ENABLED', "'yes'")
        else:
            new_manager_configuration = old_manager_configuration.replace('IPV6_ENABLED', "'no'")

        if 'ipv4' in configuration['ip_type']:
            new_configuration = old_agent_configuration.replace('<address>MANAGER_IP</address>',
                                                                f"<address>{network['manager_network'][0]}</address>")
            host_manager.modify_file_content(host='wazuh-agent1', path='/var/ossec/etc/ossec.conf',
                                             content=new_configuration)
        elif 'ipv6' in configuration['ip_type']:
            new_configuration = old_agent_configuration.replace('<address>MANAGER_IP</address>',
                                                                f"<address>{network['manager_network'][1]}</address>")
            host_manager.modify_file_content(host='wazuh-agent1', path='/var/ossec/etc/ossec.conf',
                                             content=new_configuration)
        elif 'dns' in configuration['ip_type']:
            new_configuration = old_agent_configuration.replace('<address>MANAGER_IP</address>',
                                                                '<address>wazuh-manager</address>')
            host_manager.modify_file_content(host='wazuh-agent1', path='/var/ossec/etc/ossec.conf',
                                             content=new_configuration)

    with open(manager_conf_file, 'w') as file:
        file.write(new_manager_configuration)

    host_manager.apply_config(manager_conf_file)

    yield

    with open(manager_conf_file, 'w') as file:
        file.write(old_manager_configuration)


@pytest.mark.parametrize('test_case', [cases for cases in test_cases_yaml],
                         ids=[cases['name'] for cases in test_cases_yaml])
def test_agent_keep_alive(test_case, configure_network, get_ip_directions, modify_ip_address_conf, enrollment,
                          clean_environment):
    '''
    description: Check if keep alive messages are sent in the correct format
                 and the manager sends the ACK.
    wazuh_min_version: 4.4.0
    parameters:
        - test_case:
            type: list
            brief: List of tests to be performed.
        - get_ip_directions:
            type: fixture
            brief: Get IP from the manager and the agent.
        - configure_network:
            type: fixture
            brief: Configure a custom network environment for testing.
        - modify_ip_address_conf:
            type: fixture
            brief: Add IP to test configuration.
        - clean_environment:
            type: fixture
            brief: Clean environment after every test execution.
        - enrollment:
            type: function
            brief: Register the agent
    assertions:
        - Verify that keep alives are received after registering an agent.
        - Verify that agent's info is added to global.db
    input_description: Different use cases are found in the test module and include parameters
                       for enrollment.
    expected_output:
        - '.*Checking for keys file changes.'
        - '.*Updating state file.'
        - '.*Updating shared files sums.'
        - '.*End updating shared files sums.'
        - '.*inserting.*'
        - '.*merged.mg*'
        - '.*agent_ip.*'
        - '.*reading.*'
        - '.*Sending agent notification.'
        - '.*Sending keep alive: #!-Linux |wazuh-agent1 |.*'
    tags:
        - remoted
    '''
    # Clean ossec.log and cluster.log
    host_manager.clear_file(host='wazuh-manager', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.clear_file(host='wazuh-agent1', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    sleep(wait_agent_start)

    # Run the callback checks for the ossec.log
    HostMonitor(inventory_path=inventory_path,
                messages_path=messages_path,
                tmp_path=tmp_path,
                delete_files=False).run()

    get_agent_keep_alive()
    get_manager_received_keep_alive()

    assert info == reading == inserting
    assert merged == reading_merged == inserting_merged
    assert agent_ip == reading_agent_ip == inserting_agent_ip

    agent_table = host_manager.run_db_query(host='wazuh-manager', query='SELECT * FROM agent', db_path=GLOBAL_DB_PATH)
    key = enrollment
    assert key in agent_table
    assert merged.split(' ')[0] in agent_table
    assert info.split('/ ')[1] in agent_table
