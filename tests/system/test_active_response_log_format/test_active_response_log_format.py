# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import time

import pytest
from wazuh_testing.tools import WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager

# Hosts
testinfra_hosts = ["wazuh-master", "wazuh-agent1", "wazuh-agent2", "wazuh-agent3"]
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'system','provisioning', 'manager_agent', 'inventory.yml')
host_manager = HostManager(inventory_path)

local_path = os.path.dirname(os.path.abspath(__file__))
messages_files = ['data/messages_415_or_lower.yml', 'data/messages_420_to_424.yml', 'data/messages_425_or_greater.yml']
tmp_path = os.path.join(local_path, 'tmp')
log_path = "/var/log/secure"
log_cases=["Dec  9 22:15:40 localhost sshd[5332]: Failed password for invalid user BALROG from 192.168.123.321 port 52620 $token: `132`! ssh2"]
sleep_time = 10


def clean_environment(wazuh_agent):
    # Clean ossec.log and active-responses.log
    host_manager.clear_file(host='wazuh-master', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.clear_file(host=wazuh_agent, file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.clear_file(host=wazuh_agent, file_path=os.path.join(WAZUH_LOGS_PATH, 'active-responses.log'))


@pytest.mark.parametrize('wazuh_agent, message_file', [('wazuh-agent1', messages_files[0]),
                        ('wazuh-agent2', messages_files[1]),('wazuh-agent3', messages_files[2])])
def test_active_response_log_format(wazuh_agent, message_file):
    """Check that when an Active Response is activated, the manager sends back the information to the agent
    and that it appears in active-response.log and/or ossec.log with the expected format"""

    clean_environment(wazuh_agent)
    
    # Insert log
    command = f"echo {log_cases[0]} >> {log_path}"

    # wait for active responses messages to be genrated
    time.sleep(sleep_time)
    
    # Add log message to agent monitored source
    host_manager.run_shell(host=wazuh_agent, cmd=command)

    # Run the callback checks for the ossec.log and the actibe-responses.log
    HostMonitor(inventory_path=inventory_path,
                messages_path=os.path.join(local_path,message_file),
                tmp_path=tmp_path).run()