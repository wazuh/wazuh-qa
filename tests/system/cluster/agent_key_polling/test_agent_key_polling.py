# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import wazuh_testing.system as system
from wazuh_testing.tools import WAZUH_LOGS_PATH

# Hosts
testinfra_hosts = ["wazuh-master", "wazuh-worker1", "wazuh-agent2"]
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'docker_provisioning', 'inventory.yml')


# Configuration
def configure_environment(host_manager):
    fetch_key_path = '/tmp/fetch_keys.py'
    host_manager.move_file(host='wazuh-master', src_path='files/fetch_keys.py', dest_path=fetch_key_path)
    host_manager.apply_config('data/config.yml', clear_files=[os.path.join(WAZUH_LOGS_PATH, 'ossec.log')],
                              restart_services=['wazuh'])
    host_manager.add_block_to_file(host='wazuh-master', path='/var/ossec/etc/client.keys', replace='NOTVALIDKEY',
                                   after='wazuh-agent2 any ', before='2\n')
    host_manager.clear_file(host='wazuh-agent2', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))


def test_agent_key_polling():
    host_manager = system.HostManager(inventory_path=inventory_path)
    host_monitor = system.HostMonitor(inventory_path=inventory_path,
                                      file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))

    configure_environment(host_manager)

    host_monitor.run(messages_path='data/messages.yml')
