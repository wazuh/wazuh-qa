"""
copyright: Copyright (C) 2015-2021, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: Check that when an Active Response is activated, the manager sends back the information to the agent
    and that it appears in active-response.log and ossec.log with the expected format.
tier: 1
modules:
    - active_response
components:
    - manager
    - agent
path: tests/system/test_active_response/test_active_response_log_format/test_active_response_log_format.py
daemons:
    - wazuh-execd
os_platform:
    - linux
os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6
references:
    - https://github.com/wazuh/wazuh/issues/10858
tags:
    - active_response
"""

import os
import time

import pytest
from wazuh_testing.tools import WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager

# Hosts and variables
# In order to run this test, first you need to launch the manager_agent enviroment
testinfra_hosts = ["wazuh-manager", "wazuh-agent1", "wazuh-agent2", "wazuh-agent3"]
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'system','provisioning', 'manager_agent', 'inventory.yml')
host_manager = HostManager(inventory_path)

local_path = os.path.dirname(os.path.abspath(__file__))
messages_files = ['data/messages_415_or_lower.yml', 'data/messages_420_to_424.yml', 'data/messages_425_or_greater.yml']
tmp_path = os.path.join(local_path, 'tmp')
log_path = "/var/log/secure"
log_cases=["Dec  9 22:15:40 localhost sshd[5332]: Failed password for invalid user BALROG from 192.168.222.11 port 52620 '$token': `132`! ssh2\n\n"]
sleep_time = 5


def clean_environment(wazuh_agent):
    # Clean ossec.log and active-responses.log
    host_manager.clear_file(host=wazuh_agent, file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.clear_file(host=wazuh_agent, file_path=os.path.join(WAZUH_LOGS_PATH, 'active-responses.log'))


@pytest.mark.parametrize('wazuh_agent, message_file', [('wazuh-agent1', messages_files[0]),
                        ('wazuh-agent2', messages_files[1]),('wazuh-agent3', messages_files[2])])
def test_active_response_log_format(wazuh_agent, message_file):
    """
    description: Check that when an Active Response is activated, the manager sends back the information to the agent
    and that it appears in active-response.log and ossec.log with the expected format

    wazuh_min_version: 4.2.0

    parameters:
        - wazuh_agent:
            type: string
            brief: tells which agent to insert the log message.
        - message_file:
            type: string
            brief: tells HostManager the location of the yml file with the expected messages and where to look for them
        
    input_description: Each agent has a different version with a specific yml file containing the expected messages 
                       and their location in the agent's logs
    
    expected_output: In case the test passes it will show "Received from {host} the expected message: {message}"
                     in case it failes it will show: "Did not found the expected callback in {host}: {message}"
    """

    clean_environment(wazuh_agent)
    
    # Add log message to agent monitored source
    host_manager.modify_file_content(host=wazuh_agent, path=log_path, content=log_cases[0])
    
    # wait for active responses messages to be generated
    time.sleep(sleep_time)

    # Run the callback checks for the ossec.log and the active-responses.log
    HostMonitor(inventory_path=inventory_path,
                messages_path=os.path.join(local_path,message_file),
                tmp_path=tmp_path).run()