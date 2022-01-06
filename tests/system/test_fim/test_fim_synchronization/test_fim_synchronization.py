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

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'one_manager_agent', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = os.path.join(local_path, 'data/messages.yml')
tmp_path = os.path.join(local_path, 'tmp')



def create_folder(folder_path):
    # Create folder
    host_manager.run_command('wazuh-agent1', f'mkdir {folder_path}')

    # Create file
    host_manager.run_command('wazuh-agent1', f'touch {folder_path}/{folder_path}.txt')

def delete_folder(folder_path):
    # Delete folder
    host_manager.run_command('wazuh-agent1', f'rm -rf {folder_path}')


def clean_logs():
    host_manager.clear_file(host='wazuh-manager', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    host_manager.clear_file(host='wazuh-agent1', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))

@pytest.mark.parametrize('folder_path', ['testdir1', 'testdir2', 'testdir3'])
def test_Synchronization_add_file(folder_path):
    '''
    The test will monitor a directory.
    Finally, it will verify that the FIM 'Synchronization' event is generated. 
    '''
    clean_logs()
    host_manager.create_folder(folder_path)

   
    # Restart Wazuh agent
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="restarted")

    try:
        # Run the callback checks for the ossec.log
        HostMonitor(inventory_path=inventory_path,
                    messages_path=messages_path,
                    tmp_path=tmp_path).run()
    finally:
        delete_folder(folder_path)


@pytest.mark.parametrize('folder_path', ['testdir1', 'testdir2', 'testdir3'])
def test_Synchronization_modify_file(folder_path):
    '''
    The test will monitor a directory and modify file.
    Finally, it will verify that the FIM 'Synchronization' event is generated. 
    '''
    
    create_folder(folder_path)
    clean_logs()

    # Restart Wazuh agent
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="stopped")
    host_manager.run_command('wazuh-agent1', f'echo {folder_path} >> {folder_path}/{folder_path}.txt')
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="restarted")

    try:
        # Run the callback checks for the ossec.log
        HostMonitor(inventory_path=inventory_path,
                    messages_path=messages_path,
                    tmp_path=tmp_path).run()
    finally:
        delete_folder(folder_path)
