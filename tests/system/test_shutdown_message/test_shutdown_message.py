'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: sys
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
'''

import os
import pytest
import re
import time
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.file import read_file
from wazuh_testing.tools.system import HostManager

testinfra_hosts = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
workers = ['wazuh-worker1', 'wazuh-worker2']
network = {}
agents = []
client_keys = {} 
number_agents = 40
disconnected_agents =""

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'provisioning', 'big_cluster_40_agents', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
agent_conf_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..',
                               'provisioning', 'big_cluster_40_agents', 'roles', 'agent-role', 'files', 'ossec.conf')


def get_ip_directions(hosts):
    global network
    for host in hosts:
        network[host] = host_manager.get_host_ip(host, 'eth0')
    return network

def reconfigure_agent():
    global all_infra_hosts
    unconected_agent =[]
    agent_ids = host_manager.run_command(testinfra_hosts[0], f'{WAZUH_PATH}/bin/manage_agents -l')
    for agent in agents:
        if agent not in agent_ids:
            unconected_agent.append(agent)
    if unconected_agent != []:
        get_ip_directions(all_infra_hosts)
        configure_network(unconected_agent)
        modify_ip_address_conf(unconected_agent)
        certicate_setting(unconected_agent)

def configure_network(hosts):
    for host in hosts:
        host_manager.run_command(host, 'ip -4 addr flush dev eth0')
        host_manager.run_command(host, 'ip -6 addr flush dev eth0')
        host_manager.run_command(host, f"ip addr add {network[host][0]} dev eth0")

def modify_ip_address_conf(unconfigured_agent):
    old_agent_configuration = read_file(agent_conf_file)
    new_configuration = old_agent_configuration.replace('<address>MANAGER_IP</address>',
                                                        f"<address>{network['wazuh-master'][0]}</address>")
    for agent in unconfigured_agent:
        host_manager.modify_file_content(host=agents[agents.index(agent)], path=f'{WAZUH_PATH}/etc/ossec.conf',
                                            content=new_configuration) 

def certicate_setting(agents):
    global client_keys       
    host_manager.get_host(all_infra_hosts[0]).ansible('command', f'service wazuh-manager restart', check=False)
    host_manager.control_service(host=all_infra_hosts[0], service='wazuh', state="restarted")
    for agent in agents:
        host_manager.get_host(agent).ansible('command', f'service wazuh-agent restart', check=False)
        client_keys[agent] = host_manager.get_file_content(agent, os.path.join(WAZUH_PATH, 'etc', 'client.keys')) 

def reactivate_gracefully_all_agents():
    for agent in agents:
        host_manager.run_command(agent, f'{WAZUH_PATH}/bin/wazuh-control restart')

def count_disconnected(text):
    pattern = r"Disconnected"
    matches = re.findall(pattern, text)
    count = len(matches)
    return count

@pytest.fixture
def create_agent_list():
    global agents
    global all_infra_hosts
    global testinfra_hosts
    agents = []
    for i in range(40):
        agent = f'wazuh-agent{i+1}'
        agents.append(agent)
    all_infra_hosts = testinfra_hosts + agents

@pytest.fixture        
def network_review():
    host_manager.run_command(testinfra_hosts[0], f'{WAZUH_PATH}/bin/agent_control -R -a')
    time.sleep(2)
    checkagents = host_manager.run_command(testinfra_hosts[0], f'{WAZUH_PATH}/bin/manage_agents -l')
    if '** No agent available.' in checkagents:
        get_ip_directions(all_infra_hosts)
        configure_network(all_infra_hosts)
        modify_ip_address_conf(agents)
        certicate_setting(all_infra_hosts)
    else: reconfigure_agent()

@pytest.fixture  
def restart_all_agents():
    host_manager.run_command(testinfra_hosts[0], f'{WAZUH_PATH}/bin/agent_control -R -a')
    time.sleep(2)

@pytest.fixture
def stop_gracefully_all_agents():
    for agent in agents:
        host_manager.run_command(agent, f'{WAZUH_PATH}/bin/wazuh-control stop')

@pytest.fixture          
def check_status_agents():
    global disconnected_agents
    value =""
    host_manager.get_host(all_infra_hosts[0]).ansible('command', f'service wazuh-manager restart', check=False)
    time.sleep(3)
    value = host_manager.run_command(testinfra_hosts[0], f'{WAZUH_PATH}/bin/agent_control -l')
    reactivate_gracefully_all_agents()
    disconnected_agents = count_disconnected(value)

def test_shut_down_message_gracefully_stopped_agent(create_agent_list, network_review,
                          restart_all_agents, stop_gracefully_all_agents, check_status_agents):
    '''
        description: Checking shutdown message when socket is closed.
        wazuh_min_version: 4.5.0
        parameters:
            - create_agent_list:
                type: function
                brief: Create a list of agents to be used in future operations.
            - network_review:
                type: function
                brief: Check if there are agents that are not configured to be detected by the manager and it makes the configuration.
            - restart_all_agents:
                type: function
                brief: Restart all the agents to manipulate them after.            
            - stop_gracefully_all_agents:
                type: function
                brief: Stop agents gracefully
            - check_status_agents:
                type: function
                brief: Restart the manager, check the agent status and count them.                  
        
        assertions:
            - Verify that all agents status became 'Disconnected' after gracefully shutdown.
        
        input_description: Different use cases are found in the test module and include parameters.
        
        expected_output:
            - Gracefully closed, it is expected to find agents 'Disconected' in agent-manager
        
    '''
    assert disconnected_agents == number_agents 
