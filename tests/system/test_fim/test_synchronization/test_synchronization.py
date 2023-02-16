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
path: tests/system/test_fim/test_fim_synchronization/test_fim_synchronization.py
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
    - https://github.com/wazuh/wazuh-qa/issues/2434
tags:
    - fim_synchronization
"""

import os
import json
import pytest
from time import sleep


from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager, clean_environment
from wazuh_testing.tools import WAZUH_LOGS_PATH
from wazuh_testing.fim import create_folder_file, query_db


pytestmark = [pytest.mark.one_manager_agent_env]


# Hosts
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'one_manager_agent', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = [os.path.join(local_path, 'data/messages.yml'),
                 os.path.join(local_path, 'data/delete_message.yml'),
                 os.path.join(local_path, 'data/wait_fim_scan.yml'),
                 os.path.join(local_path, 'data/agent_initializing_synchronization.yml'),
                 os.path.join(local_path, 'data/manager_initializing_synchronization.yml')
                 ]
tmp_path = os.path.join(local_path, 'tmp')
scheduled_mode = 'testdir1'
db_path = '/var/ossec/queue/db/001.db'
db_script = '/var/system_query_db.py'
enviroment_files = [('wazuh-manager', os.path.join(WAZUH_LOGS_PATH, 'ossec.log')),
                    ('wazuh-agent1', os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))]


@pytest.mark.parametrize('host', ['wazuh-agent1', 'wazuh-manager'])
@pytest.mark.parametrize('case', ['add', 'modify', 'delete'])
@pytest.mark.parametrize('folder_path', ['testdir1'])
def test_synchronization(folder_path, case, host):
    '''
    Description: The test will monitor a directory and apply changes when agent/manager is stopped.
    Finally, it will verify that the FIM 'Synchronization' event is generated
    in agent and manager side.

    wazuh_min_version: 4.2.0

    parameters:
        - folder_path:
            type: str
            brief: Name of the folder that will be created in the test.
        - case:
            type: str
            brief: Name of the test case that will be created in the test.
        - host:
            type: str
            brief: Name of the endpoint  that will be use in the test.

    assertions:
        - Verify that FIM sync events are generated correctly on the manager and agent sides.

    input_description: Different test cases are included with Pytest parametrize.
                       The test cases are: add, modify and delete files.

    expected_output:
        - Different test cases are contained in external YAML file
          (agent_initializing_synchronization.yml and manager_initializing_synchronization.yml)
    tags:
        - fim_basic_usage
        - scheduled
    '''
    message_path = messages_path[3]
    # Clear logs, create folder to monitored and restart the service
    create_folder_file(host_manager, folder_path)
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="restarted")

    # Check that the manager contains data to monitor
    try:
        HostMonitor(inventory_path=inventory_path,
                    messages_path=messages_path[0],
                    tmp_path=tmp_path).run()
    except:
        host_manager.run_command('wazuh-agent1', f'rm -rf {folder_path}')

    clean_environment(host_manager, enviroment_files)

    # Stop host
    host_manager.run_command(host, '/var/ossec/bin/wazuh-control stop')

    if (case == 'add'):
        host_manager.run_command('wazuh-agent1', f'touch {folder_path}/{folder_path}.txt')

    elif(case == 'modify'):
        host_manager.modify_file_content(host='wazuh-agent1', path=folder_path, content=folder_path)

    else:
        host_manager.run_command('wazuh-agent1', f'rm -rf {folder_path}')
        folder_path = f"'/{folder_path}/{folder_path}.txt'"
        query = " select * from fim_entry where full_path='\"{}\"'".format(folder_path)

    # Start host
    host_manager.run_command(host, '/var/ossec/bin/wazuh-control start')

    if (host == 'wazuh-manager'):
        message_path = messages_path[4]

    try:
        HostMonitor(inventory_path=inventory_path,
                    messages_path=message_path,
                    tmp_path=tmp_path).run()
        if (case == 'delete'):
            # Execute query to DB
            sleep(5)
            result = query_db(host_manager, db_script, db_path, f'\"{query}\"')
            assert not json.loads(result)

    finally:
        host_manager.run_command('wazuh-agent1', f'rm -rf {folder_path}')
