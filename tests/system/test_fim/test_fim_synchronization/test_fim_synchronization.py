"""
copyright: Copyright (C) 2015-2021, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: Check that when FIM is activated, and the agent is running, the agent and manager are synchronization when
a change is performed in a monitored folder.
tier: 1
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
    - https://github.com/wazuh/wazuh-qa/issues/2389
tags:
    - fim_synchronization
"""

import os

import pytest
from wazuh_testing.tools import WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager


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


def create_folder(folder_path):
    # Create folder
    host_manager.run_command('wazuh-agent1', f'mkdir {folder_path}')

    # Create file
    host_manager.run_command('wazuh-agent1', f'touch {folder_path}/{folder_path}.txt')


def clean_logs():
    host_manager.clear_file(host='wazuh-manager', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.clear_file(host='wazuh-agent1', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))


def wait_for_fim_scan_end(folder_path):
    try:
        HostMonitor(inventory_path=inventory_path,
                    messages_path=messages_path[2],
                    tmp_path=tmp_path).run()
    finally:
        host_manager.run_command('wazuh-agent1', f'rm -rf {folder_path}')


@pytest.mark.parametrize('folder_path', ['testdir1', 'testdir2', 'testdir3'])
def test_Synchronization_add_file(folder_path):
    '''
    The test will monitor a directory.
    Finally, it will verify that the FIM event is generated
    in agent and manager side.
    '''
    clean_logs()
    create_folder(folder_path)

    # Restart Wazuh agent
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="restarted")

    # Check if the scan monitors end
    if (folder_path == scheduled_mode):
        wait_for_fim_scan_end(folder_path)

    try:
        # Run the callback checks for the ossec.log
        HostMonitor(inventory_path=inventory_path,
                    messages_path=messages_path[0],
                    tmp_path=tmp_path).run()
    finally:
        host_manager.run_command('wazuh-agent1', f'rm -rf {folder_path}')


@pytest.mark.parametrize('folder_path', ['testdir1', 'testdir2', 'testdir3'])
def test_Synchronization_modify_file(folder_path):
    '''
    The test will monitor a directory and modify file.
    Finally, it will verify that the FIM event is generated
    in agent and manager side.
    '''
    # Clear logs, create folder to monitored and restart the service
    clean_logs()
    create_folder(folder_path)
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="restarted")

    # Check if the scan monitors end
    if (folder_path == scheduled_mode):
        wait_for_fim_scan_end(folder_path)

    # Modify file
    host_manager.modify_file_content(host='wazuh-agent1', path=folder_path, content=folder_path)

    try:
        # Run the callback checks for the ossec.log
        HostMonitor(inventory_path=inventory_path,
                    messages_path=messages_path[0],
                    tmp_path=tmp_path).run()
    finally:
        host_manager.run_command('wazuh-agent1', f'rm -rf {folder_path}')


@pytest.mark.parametrize('folder_path', ['testdir1', 'testdir2', 'testdir3'])
def test_Synchronization_delete_file(folder_path):
    '''
    The test will monitor a directory and modify file.
    Finally, it will verify that the FIM 'Synchronization' event is generated
    in agent and manager side.
    '''
    # Clear logs, create folder to monitored and restart the service
    clean_logs()
    create_folder(folder_path)
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="restarted")

    # Check if the scan monitors end in module scheduled
    if (folder_path == scheduled_mode):
        wait_for_fim_scan_end(folder_path)

    # Delete folder
    host_manager.run_command('wazuh-agent1', f'rm -rf {folder_path}')

    try:
        # Run the callback checks for the ossec.log
        HostMonitor(inventory_path=inventory_path,
                    messages_path=messages_path[0],
                    tmp_path=tmp_path).run()
    finally:
        host_manager.run_command('wazuh-agent1', f'rm -rf {folder_path}')
