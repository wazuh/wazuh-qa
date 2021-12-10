# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager

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
manager_conf_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..',
                                'provisioning', 'basic_environment', 'roles', 'manager-role', 'files', 'ossec.conf')


network_configuration = [
    {
        'name': 'manager_ipv4_agent_ipv4',
        'wazuh-manager': 'ipv4',
        'wazuh-agent1': 'ipv4'
    },
    {
        'name': 'manager_ipv6_agent_ipv4',
        'wazuh-manager': 'ipv6',
        'wazuh-agent1': 'ipv4'
    },
    {
        'name': 'manager_ipv4_agent_ipv6',
        'wazuh-manager': 'ipv4',
        'wazuh-agent1': 'ipv6'
    },
    {
        'name': 'manager_ipv6_agent_ipv6',
        'wazuh-manager': 'ipv6',
        'wazuh-agent1': 'ipv6'
    },
    {
        'name': 'manager_dns_agent_ipv4',
        'wazuh-manager': 'dns',
        'wazuh-agent1': 'ipv4'
    },
    {
        'name': 'manager_dns_agent_ipv6',
        'wazuh-manager': 'dns',
        'wazuh-agent1': 'ipv6'
    }
]

network = {}


# Remove the agent once the test has finished
@pytest.fixture(scope='function')
def clean_environment():
    yield
    agent_id = host_manager.run_command('wazuh-manager', f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys')
    host_manager.get_host('wazuh-manager').ansible("command", f'{WAZUH_PATH}/bin/manage_agents -r {agent_id}',
                                                  check=False)
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="stopped")
    host_manager.clear_file(host='wazuh-agent1', file_path=os.path.join(WAZUH_PATH, 'etc', 'client.keys'))


@pytest.mark.parametrize('ipv6_enabled', ['yes', 'no'])
@pytest.mark.parametrize('test_case', [cases for cases in network_configuration], ids = [cases['name'] for cases in network_configuration])
def test_agent_auth(test_case, ipv6_enabled, get_ip_directions, configure_network, modify_ip_address_conf, clean_environment):
    """Check agent enrollment process works as expected. An agent pointing to a worker should be able to register itself
    into the manager by starting Wazuh-agent process."""
    # Clean ossec.log and cluster.log
    host_manager.clear_file(host='wazuh-manager', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.clear_file(host='wazuh-agent1', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))

    # Start the agent enrollment process using agent-auth
    if 'ipv4' in test_case['wazuh-manager']:
        host_manager.run_command('wazuh-agent1', f"{WAZUH_PATH}/bin/agent-auth -m {network['manager_network'][0]}")
    elif 'ipv6' in test_case['wazuh-manager']:
        host_manager.run_command('wazuh-agent1', f"{WAZUH_PATH}/bin/agent-auth -m {network['manager_network'][1]}")
    else:
        host_manager.run_command('wazuh-agent1', f"{WAZUH_PATH}/bin/agent-auth -m wazuh-manager")

    # Run the callback checks for the ossec.log
    HostMonitor(inventory_path=inventory_path,
                messages_path=messages_path,
                tmp_path=tmp_path).run()

    # Make sure the agent's client.keys is not empty
    assert host_manager.get_file_content('wazuh-agent1', os.path.join(WAZUH_PATH, 'etc', 'client.keys'))

    # Check if the agent is active
    agent_id = host_manager.run_command('wazuh-manager', f'cut -c 1-3 {WAZUH_PATH}/etc/client.keys')
    assert host_manager.run_command('wazuh-manager', f'{WAZUH_PATH}/bin/agent_control -i {agent_id} | grep Active')

# IPV6 fixtures
@pytest.fixture(scope='module')
def get_ip_directions():
    global network

    manager_network = host_manager.get_host_ip('wazuh-manager')
    agent_network = host_manager.get_host_ip('wazuh-agent1')

    network['manager_network'] = manager_network
    network['agent_network'] = agent_network


@pytest.fixture(scope='function')
def configure_network(test_case):

    if 'ipv6' in test_case['wazuh-agent1']:
        host_manager.run_command('wazuh-agent1', 'ip -4 addr flush dev eth0')
    elif 'ipv4' in test_case['wazuh-agent1']:
        host_manager.run_command('wazuh-agent1', 'ip -6 addr flush dev eth0')

    yield

    if 'ipv6' in test_case['wazuh-agent1']:
        host_manager.run_command('wazuh-agent1', f"ip addr add {network['agent_network'][0]} dev eth0")
    elif 'ipv4' in test_case['wazuh-agent1']:
        host_manager.run_command('wazuh-agent1', f"ip addr add {network['agent_network'][1]} dev eth0")


@pytest.fixture(scope='function')
def modify_ip_address_conf(test_case, ipv6_enabled):

    with open(messages_path, 'r') as file:
        messages = file.read()

    with open(manager_conf_file, 'r') as file:
	    old_manager_configuration = file.read()

    if 'yes' in ipv6_enabled:
        new_manager_configuration = old_manager_configuration.replace('<ipv6>no</ipv6>','<ipv6>yes</ipv6>')
        host_manager.modify_file_content(host='wazuh-manager', path='/var/ossec/etc/ossec.conf', content=new_manager_configuration)

    if 'ipv4' in test_case['wazuh-manager']:
        messages_with_ip = messages.replace('MANAGER_IP', f"{network['manager_network'][0]}")

    elif 'ipv6' in test_case['wazuh-manager']:
        messages_with_ip = messages.replace('MANAGER_IP', f"{network['manager_network'][1]}")
    else:
        messages_with_ip = messages.replace('MANAGER_IP', f"{network['manager_network'][1]}")

    if 'ipv4' in test_case['wazuh-agent1']:
        if 'yes' in ipv6_enabled:
            messages_with_ip = messages_with_ip.replace('AGENT_IP', f"::ffff:{network['agent_network'][0]}")
        else:
            messages_with_ip = messages_with_ip.replace('AGENT_IP', f"{network['agent_network'][0]}")
    elif 'ipv6' in test_case['wazuh-agent1']:
        messages_with_ip = messages_with_ip.replace('AGENT_IP', f"{network['agent_network'][1]}")

    with open(messages_path, 'w') as file:
            file.write(messages_with_ip)

    yield

    with open(messages_path, 'w') as file:
            file.write(messages)
