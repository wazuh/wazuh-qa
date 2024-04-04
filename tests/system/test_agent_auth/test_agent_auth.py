'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: The agent-auth program is the client application used along with 'wazuh-authd' to automatically add agents to a
       Wazuh manager. These tests will check if the 'wazuh-authd' daemon processes registration messages correctly.
tier: 0
modules:
    - enrollment
components:
    - manager
    - agent
daemons:
    - wazuh-authd
os_platform:
    - linux
os_version:
    - Debian Buster
references:
    - https://documentation.wazuh.com/current/user-manual/reference/tools/agent-auth.html
tags:
    - authd
'''

import os
from time import sleep

import pytest

from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.tools.system_monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools.utils import format_ipv6_long


pytestmark = [pytest.mark.basic_environment_env]
TIMEOUT_AFTER_RESTART = 5

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
test_cases_yaml = read_yaml(os.path.join(local_path, 'data/test_agent_auth_cases.yml'))

wait_agent_start = 20
network = {}


# Remove the agent once the test has finished
@pytest.fixture(scope='function')
def clean_environment():
    yield
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="stopped")
    agent_id = host_manager.run_command('wazuh-manager', f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys')
    host_manager.run_command('wazuh-manager', f"{WAZUH_PATH}/bin/manage_agents -r {agent_id}")
    host_manager.clear_file(host='wazuh-manager', file_path=os.path.join(WAZUH_PATH, 'etc', 'client.keys'))
    host_manager.clear_file(host='wazuh-agent1', file_path=os.path.join(WAZUH_PATH, 'etc', 'client.keys'))
    host_manager.clear_file(host='wazuh-agent1', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))


# IPV6 fixtures
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

    with open(messages_path, 'r') as file:
        messages = file.read()

    with open(manager_conf_file, 'r') as file:
        old_manager_configuration = file.read()

    expected_message_agent_ip = ''
    expected_message_manager_ip = ''

    for configuration in test_case['test_case']:
        if 'yes' in configuration['ipv6_enabled']:
            new_manager_configuration = old_manager_configuration.replace('IPV6_ENABLED', "'yes'")
        else:
            new_manager_configuration = old_manager_configuration.replace('IPV6_ENABLED', "'no'")

        if 'ipv4' in configuration['ip_type']:
            expected_message_manager_ip = network['manager_network'][0]

        elif 'ipv6' in configuration['ip_type']:
            expected_message_manager_ip = format_ipv6_long(network['manager_network'][1])

        elif 'dns' in configuration['ip_type']:
            expected_message_manager_ip = 'wazuh-manager'

        new_configuration = old_agent_configuration.replace('<address>MANAGER_IP</address>',
                                                            f"<address>{expected_message_manager_ip}</address>")
        host_manager.modify_file_content(host='wazuh-agent1', path='/var/ossec/etc/ossec.conf',
                                         content=new_configuration)

        formatted_regex_ip = expected_message_manager_ip.replace(r'-', r'\\-')
        formatted_regex_ip = formatted_regex_ip.replace(r'.', r'\\.')

        messages_with_ip = messages.replace('MANAGER_IP', f"{formatted_regex_ip}")

        if 'ipv4' in configuration['ip_type']:
            expected_message_agent_ip = network['agent_network'][0]
        elif 'ipv6' in configuration['ip_type']:
            expected_message_agent_ip = format_ipv6_long(network['agent_network'][1])

        elif 'dns' in configuration['ip_type']:
            if 'yes' in configuration['ipv6_enabled']:
                if 'ipv4' in configuration['agent_network'] or 'ipv4' in configuration['manager_network']:
                    expected_message_agent_ip = network['agent_network'][0]
                else:
                    expected_message_agent_ip = format_ipv6_long(network['agent_network'][1])
            else:
                expected_message_agent_ip = network['agent_network'][0]

        formatted_regex_ip = expected_message_agent_ip.replace('-', r'\\-')
        formatted_regex_ip = formatted_regex_ip.replace('.', r'\\.')

        messages_with_ip = messages_with_ip.replace('AGENT_IP', f"{formatted_regex_ip}")

    with open(manager_conf_file, 'w') as file:
        file.write(new_manager_configuration)

    host_manager.apply_config(manager_conf_file)

    with open(messages_path, 'w') as file:
        file.write(messages_with_ip)

    yield

    with open(messages_path, 'w') as file:
        file.write(messages)

    with open(manager_conf_file, 'w') as file:
        file.write(old_manager_configuration)


@pytest.mark.parametrize('test_case', [cases for cases in test_cases_yaml], ids=[cases['name']
                         for cases in test_cases_yaml])
def test_agent_auth(test_case, get_ip_directions, configure_network, modify_ip_address_conf, clean_environment):
    '''
    description: Check if 'agent-auth' messages are sent in the correct format
                 and the agent is registered and connected.
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
    assertions:
        - Verify that expected logs are received after registering an agent with 'agent-auth' tool.
        - Verify that 'client.keys' are equal in manager and agent.
        - Verify that the agent is 'Active'
    input_description: Different use cases are found in the test module and include parameters
                       for 'agent-auth' messages.
    expected_output:
        - '.*New connection from AGENT_IP'
        - '.*Received request for a new agent .* from: AGENT_IP'
        - '.*Agent key generated for.*'
        - '.*Requesting a key from server: MANAGER_IP'
        - '.*No authentication password provided'
        - '.*Using agent name as:*'
        - '.*Waiting for server reply'
        - '.*Valid key received'
    tags:
        - authd
    '''
    # Clean ossec.log and cluster.log
    host_manager.clear_file(host='wazuh-manager', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.control_service(host='wazuh-manager', service='wazuh', state="restarted")

    sleep(TIMEOUT_AFTER_RESTART)

    # Start the agent enrollment process using agent-auth
    for configuration in test_case['test_case']:
        if 'ipv4' in configuration['ip_type']:
            host_manager.run_command('wazuh-agent1', f"{WAZUH_PATH}/bin/agent-auth -m {network['manager_network'][0]}")
        elif 'ipv6' in configuration['ip_type']:
            host_manager.run_command('wazuh-agent1', f"{WAZUH_PATH}/bin/agent-auth -m {network['manager_network'][1]}")
        else:
            host_manager.run_command('wazuh-agent1', f"{WAZUH_PATH}/bin/agent-auth -m wazuh-manager")

    # Run the callback checks for the ossec.log
    HostMonitor(inventory_path=inventory_path,
                messages_path=messages_path,
                tmp_path=tmp_path).run(update_position=True)

    # Start the agent and the manager to connect them
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="started")

    # Make sure the agent's and manager's client.keys have the same keys
    agent_client_keys = host_manager.get_file_content('wazuh-agent1', os.path.join(WAZUH_PATH, 'etc', 'client.keys'))
    manager_client_keys = host_manager.get_file_content('wazuh-agent1', os.path.join(WAZUH_PATH, 'etc', 'client.keys'))
    assert agent_client_keys == manager_client_keys

    # Check if the agent is active
    agent_id = host_manager.run_command('wazuh-manager', f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys')

    sleep(wait_agent_start)

    agent_info = host_manager.run_command('wazuh-manager', f'{WAZUH_PATH}/bin/agent_control -i {agent_id}')
    assert 'Active' in agent_info
