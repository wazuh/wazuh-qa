# copyright: Copyright (C) 2015-2021, Wazuh Inc.
#           Created by Wazuh, Inc. <info@wazuh.com>.
#           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
from wazuh_testing.tools import WAZUH_LOGS_PATH


def create_folder_file(host_manager, folder_path):
    # Create folder
    host_manager.run_command('wazuh-agent1', f'mkdir {folder_path}')

    # Create file
    host_manager.run_command('wazuh-agent1', f'touch {folder_path}/{folder_path}.txt')


def wait_for_fim_scan_end(HostMonitor, inventory_path, messages_path, tmp_path):
    HostMonitor(inventory_path=inventory_path,
                messages_path=messages_path,
                tmp_path=tmp_path).run()

