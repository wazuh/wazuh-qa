'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: Wazuh includes a registration process that provides the user with an automated mechanism to enroll agents with
       minimal configuration steps. To register an agent using the enrollment method, a manager with a valid IP needs
       to be configured first. The agent then checks for the registration key in the client.keys file, and when the file
       is empty, it automatically requests the key from the configured manager the agent is reporting to.
tier: 0
modules:
    - enrollment
components:
    - manager
    - agent
daemons:
    - wazuh-authd
    - wazuh-agentd
os_platform:
    - linux
os_version:
    - Debian Buster
references:
    - https://documentation.wazuh.com/current/user-manual/registering/agent-enrollment.html
tags:
    - authd
    - agentd
'''

import os
from time import sleep

import pytest

from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.file import read_file, read_yaml, write_file
from wazuh_testing.tools.system_monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools.utils import format_ipv6_long


pytestmark = [pytest.mark.basic_environment_env]

# Hosts
testinfra_hosts = ['wazuh-manager', 'wazuh-agent1']


inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'provisioning', 'basic_environment', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = os.path.join(local_path, 'data/messages.yml')
tmp_path = os.path.join(local_path, 'tmp')
agent_conf_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..',
                               'provisioning', 'basic_environment', 'roles', 'agent-role', 'files', 'ossec.conf')
manager_conf_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data/config.yml')
test_cases_yaml = read_yaml(os.path.join(local_path, 'data/test_enrollment_cases.yml'))

wait_agent_start = 20
network = {}


# Remove the agent once the test has finished
@pytest.fixture(scope='function')
def clean_environment():
    yield
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="stopped")

    agent_ids = host_manager.run_command('wazuh-manager', f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys').split()
    for agent_id in agent_ids:
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

    # Manager network configuration
    if 'ipv6' in test_case['manager_network']:
        host_manager.run_command('wazuh-manager', 'ip -4 addr flush dev eth0')
    elif 'ipv4' in test_case['manager_network']:
        host_manager.run_command('wazuh-manager', 'ip -6 addr flush dev eth0')
    # Agent network configuration
    if 'ipv6' in test_case['agent_network']:
        host_manager.run_command('wazuh-agent1', 'ip -4 addr flush dev eth0')
    elif 'ipv4' in test_case['agent_network']:
        host_manager.run_command('wazuh-agent1', 'ip -6 addr flush dev eth0')

    yield

    # Restore manager network configuration
    if 'ipv6' in test_case['manager_network']:
        host_manager.run_command('wazuh-manager', f"ip addr add {network['manager_network'][0]} dev eth0")
        host_manager.run_command('wazuh-manager', 'ip route add 172.24.27.0/24 via 0.0.0.0 dev eth0')
    elif 'ipv4' in test_case['manager_network']:
        host_manager.run_command('wazuh-manager', f"ip addr add {network['manager_network'][1]} dev eth0")
        host_manager.run_command('wazuh-manager', f"ip addr add {network['manager_network'][2]} dev eth0")
    # Restore agent network configuration
    if 'ipv6' in test_case['agent_network']:
        host_manager.run_command('wazuh-agent1', f"ip addr add {network['agent_network'][0]} dev eth0")
        host_manager.run_command('wazuh-agent1', 'ip route add 172.24.27.0/24 via 0.0.0.0 dev eth0')
    elif 'ipv4' in test_case['agent_network']:
        host_manager.run_command('wazuh-agent1', f"ip addr add {network['agent_network'][1]} dev eth0")
        host_manager.run_command('wazuh-agent1', f"ip addr add {network['agent_network'][2]} dev eth0")


@pytest.fixture(scope='function')
def modify_ip_address_conf(test_case):

    old_agent_configuration = read_file(agent_conf_file)

    messages = read_file(messages_path)

    old_manager_configuration = read_file(manager_conf_file)
    new_manager_configuration = old_manager_configuration.replace('IPV6_ENABLED', f"'{test_case['ipv6_enabled']}'")
    write_file(manager_conf_file, new_manager_configuration)
    host_manager.apply_config(manager_conf_file)

    address_ip = ''
    message_ip_manager = ''
    message_ip_agent = ''
    message_address_manager = ''
    final_message = ''

    if test_case['ip_type'] == 'ipv4':
        address_ip = network['manager_network'][0]
        message_address_manager = message_ip_manager = address_ip
        message_ip_agent = network['agent_network'][0]
    elif test_case['ip_type'] == 'ipv6':
        address_ip = network['manager_network'][1]
        message_address_manager = message_ip_manager = format_ipv6_long(address_ip)
        message_ip_agent = format_ipv6_long(network['agent_network'][1])
    elif test_case['ip_type'] == 'dns':
        address_ip = 'wazuh-manager'
        message_address_manager = address_ip
        if test_case['ipv6_enabled'] == 'yes':
            if 'ipv4' in test_case['manager_network'] or 'ipv4' in test_case['agent_network']:
                message_ip_manager = f"{network['manager_network'][0]}"
                message_ip_agent = network['agent_network'][0]
            else:
                message_ip_manager = format_ipv6_long(network['manager_network'][1])
                message_ip_agent = format_ipv6_long(network['agent_network'][1])
        else:
            message_ip_manager = f"{network['manager_network'][0]}"
            message_ip_agent = network['agent_network'][0]

    new_configuration = old_agent_configuration.replace('<address>MANAGER_IP</address>',
                                                        f"<address>{address_ip}</address>")
    host_manager.modify_file_content(host='wazuh-agent1', path='/var/ossec/etc/ossec.conf',
                                     content=new_configuration)
    message_address_manager = message_address_manager.replace(r'-', r'\\-')
    message_with_manager_address = messages.replace(r'MANAGER_ADDRESS', message_address_manager)
    message_with_manager_ip = message_with_manager_address.replace('MANAGER_IP', message_ip_manager)
    final_message = message_with_manager_ip.replace('AGENT_IP', message_ip_agent)
    write_file(messages_path, final_message)

    yield

    write_file(messages_path, messages)

    write_file(manager_conf_file, old_manager_configuration)


@pytest.mark.parametrize('test_case', [cases['test_case'] for cases in test_cases_yaml], ids=[cases['name']
                         for cases in test_cases_yaml])
def test_agent_enrollment(test_case, get_ip_directions, configure_network, modify_ip_address_conf, clean_environment):
    '''
    description: Check if enrollment messages are sent in the correct format
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
        - Verify that expected logs are received after registering an agent.
        - Verify that 'client.keys' are equal in manager and agent.
        - Verify that the agent is 'Active'
    input_description: Different use cases are found in the test module and include parameters
                       for 'agent-auth' messages.
    expected_output:
        - '.*Received request for a new agent .* from: AGENT_IP'
        - '.*Agent key generated for.*'
        - '.*Server IP Address: MANAGER_IP'
        - '.*Requesting a key from server: MANAGER_IP'
        - '.*Registering agent to unverified manager'
        - '.*Using agent name as:*'
        - '.*Waiting for server reply'
        - '.*Valid key received'
        - '.*Waiting .* seconds before server connection'
    tags:
        - authd
        - agentd
    '''
    # Clean ossec.log and cluster.log
    host_manager.clear_file(host='wazuh-manager', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))

    # Start the agent enrollment process by restarting the wazuh-agent
    host_manager.control_service(host='wazuh-manager', service='wazuh', state="restarted")
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="restarted")

    # Run the callback checks for the ossec.log
    HostMonitor(inventory_path=inventory_path,
                messages_path=messages_path,
                tmp_path=tmp_path).run()

    # Make sure the agent's and manager's client.keys have the same keys
    agent_client_keys = host_manager.get_file_content('wazuh-agent1', os.path.join(WAZUH_PATH, 'etc', 'client.keys'))
    manager_client_keys = host_manager.get_file_content('wazuh-agent1', os.path.join(WAZUH_PATH, 'etc', 'client.keys'))

    assert agent_client_keys == manager_client_keys

    # Check if the agent is active
    agent_id = host_manager.run_command('wazuh-manager', f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys')
    sleep(wait_agent_start)
    agent_info = host_manager.run_command('wazuh-manager', f'{WAZUH_PATH}/bin/agent_control -i {agent_id}')
    assert 'Active' in agent_info
