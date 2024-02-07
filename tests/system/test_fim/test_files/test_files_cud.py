"""
copyright: Copyright (C) 2015-2021, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: Check that when FIM is activated, and the agent is running, the agent and manager are synchronization when
a change is performed in a monitored folder.
tier: 0
modules:
    - fim
components:
    - manager
    - agent
path: tests/system/test_fim/test_fim_synchronization/test_files_cud.py
daemons:
    - wazuh-syscheckd
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
    - https://github.com/wazuh/wazuh-qa/issues/2389
tags:
    - fim_basic_usage
"""

import os

import pytest
from wazuh_testing.tools.system_monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager, clean_environment
from wazuh_testing.tools import WAZUH_LOGS_PATH
from wazuh_testing.fim import create_folder_file, wait_for_fim_scan_end


pytestmark = [pytest.mark.one_manager_agent_env]

# Hosts
testinfra_hosts = ["wazuh-manager", "wazuh-agent1"]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'one_manager_agent', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = [os.path.join(local_path, 'data/messages.yml'),
                 os.path.join(local_path, 'data/delete_message.yml'),
                 os.path.join(local_path, 'data/wait_fim_scan.yml')]
tmp_path = os.path.join(local_path, 'tmp')
scheduled_mode = 'testdir1'


@pytest.mark.parametrize('case', ['add', 'modify', 'delete'])
@pytest.mark.parametrize('folder_path', ['testdir1', 'testdir2', 'testdir3'])
def test_file_cud(folder_path, case):
    '''

    description:  The test will monitor a directory.
                  Finally, it will verify that the FIM event is generated
                  in agent and manager side.

    wazuh_min_version: 4.2.0

    parameters:
        - folder_path:
            type: str
            brief: Name of the folder that will be created in the test.
        - case:
            type: str
            brief: Name of the test case that will be created in the test.

    assertions:
        - Verify that FIM events are generated correctly on the manager and agent sides.

    input_description: Different test cases are included with Pytest parametrize.
                       The test cases are: add, modify and delete files.

    expected_output:
        - Different test cases are contained in external YAML file (delete_message.yml and messages.yml)

    tags:
        - fim_basic_usage
        - scheduled
        - realtime
        - who_data
    '''
    messages = messages_path[0]
    enviroment_files = [('wazuh-manager', os.path.join(WAZUH_LOGS_PATH, 'ossec.log')),
                        ('wazuh-agent1', os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))]
    clean_environment(host_manager, enviroment_files)
    create_folder_file(host_manager, folder_path)

    # Restart Wazuh agent
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="restarted")

    # Check if the scan monitors end
    if (folder_path == scheduled_mode):
        wait_for_fim_scan_end(HostMonitor, inventory_path, messages_path[2], tmp_path)

    if (case == 'modify'):
        host_manager.modify_file_content(host='wazuh-agent1', path=folder_path, content=folder_path)

    elif(case == 'delete'):
        host_manager.run_command('wazuh-agent1', f'rm -rf {folder_path}')
        messages = messages_path[1]

    try:
        # Run the callback checks for the ossec.log
        HostMonitor(inventory_path=inventory_path,
                    messages_path=messages,
                    tmp_path=tmp_path).run()
    finally:
        host_manager.run_command('wazuh-agent1', f'rm -rf {folder_path}')
