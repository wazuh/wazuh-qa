# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager

# Hosts
testinfra_hosts = ["wazuh-master", "wazuh-agent1", "wazuh-agent2", "wazuh-agent3"]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'manager_agent', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
messages_files = ['data/messages_415_or_lower', 'data/messages_420_to_424', 'data/messages_425_or_greater']
tmp_path = os.path.join(local_path, 'tmp')
log_path = "/var/log/secure"
log_examples=["Dec  2 22:30:40 localhost sshd[5332]: Failed password for invalid user Gandalf from 192.168.111.222 port 52620",
              "Dec  2 22:30:40 localhost sshd[5332]: Failed password for invalid user Balrog from 192.168.222.111 port 52620 'touch /tmp/injection; $token: 132!' ssh2"]



def clean_environment(wazuh_agent):
    # Clean ossec.log and active-responses.log
    host_manager.clear_file(host='wazuh-master', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.clear_file(host=wazuh_agent, file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.clear_file(host=wazuh_agent, file_path=os.path.join(WAZUH_LOGS_PATH, 'active-responses.log'))


@pytest.mark.parametrize("extra_arg", "expected_arg", [({'"', '\"'}),({'!', '\!'}),({'$', '\$'}) ])
def test_active_response_log_version_415_or_lower():
    """Check that when an Active Response is activated, the manager sends back the information to the agent
    and that it appears in active-response.log and/or ossec.log with the expected format"""
    clean_environment('wazuh-agent1')

    # Add log message to agent monitored source
    host_manager.modify_file_content(host='wazuh-agent1', path=log_path, content=log_examples[0])

    # Run the callback checks for the ossec.log and the active-responses.log
    HostMonitor(inventory_path=inventory_path,
                messages_path= os.path.join(local_path, messages_files[0]),
                tmp_path=tmp_path).run()



@pytest.mark.parametrize("case_log", log_examples)
def test_active_response_log_version_420_to_424(case_log):
    """Check that when an Active Response is activated, the manager sends back the information to the agent
    and that it appears in active-response.log and/or ossec.log with the expected format"""

    clean_environment('wazuh-agent2')
    
    command = f"cat {case_log} > {log_path}"
    # Add log message to agent monitored source
    host_manager.run_shell(host='wazuh-agent2', cmd=command)

    # Run the callback checks for the ossec.log and the actibe-responses.log
    HostMonitor(inventory_path=inventory_path,
                messages_path=os.path.join(local_path, messages_files[1]),
                tmp_path=tmp_path).run()



@pytest.mark.parametrize("case_log", log_examples)
def test_active_response_log_version_425_or_greater(case_log):
    """Check that when an Active Response is activated, the manager sends back the information to the agent
    and that it appears in active-response.log and/or ossec.log with the expected format"""

    clean_environment('wazuh-agent3')
    
    command = f"cat case_log > {log_path}"
    # Add log message to agent monitored source
    host_manager.run_shell(host='wazuh-agent2', cmd=command)

    # Run the callback checks for the ossec.log and the actibe-responses.log
    HostMonitor(inventory_path=inventory_path,
                messages_path=os.path.join(local_path, messages_files[2]),
                tmp_path=tmp_path).run()
