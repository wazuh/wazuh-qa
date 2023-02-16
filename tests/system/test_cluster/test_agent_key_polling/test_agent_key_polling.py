# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing.tools import WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager

# Hosts
testinfra_hosts = ["wazuh-master", "wazuh-worker1", "wazuh-agent2"]
pytestmark = [pytest.mark.cluster, pytest.mark.basic_cluster_env]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'basic_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)


# Configuration
def configure_environment(host_manager):
    """Configure the environment to perform the test.

    Parameters
    ----------
    host_manager : system.HostManager
        Instance of HostManager
    """
    host_manager.move_file(host='wazuh-master',
                           src_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'files/fetch_keys.py'),
                           dest_path='/tmp/fetch_keys.py')
    host_manager.apply_config(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data/config.yml'),
                              clear_files=[os.path.join(WAZUH_LOGS_PATH, 'ossec.log')],
                              restart_services=['wazuh'])
    host_manager.add_block_to_file(host='wazuh-master', path='/var/ossec/etc/client.keys', replace='NOTVALIDKEY',
                                   after='wazuh-agent2 any ', before='2\n')
    host_manager.clear_file(host='wazuh-agent2', file_path=os.path.join(WAZUH_LOGS_PATH, 'ossec.log'))
    agent2_id = host_manager.run_shell(host='wazuh-master',
                                       cmd='/var/ossec/bin/manage_agents -l | grep "wazuh-agent2" | '
                                           'grep -o "[0-9][0-9][0-9]"')
    host_manager.run_shell(host='wazuh-master', cmd=f'/var/ossec/bin/manage_agents -r {agent2_id}')


def test_agent_key_polling():
    """Check that the agent key polling cycle works correctly. To do this, we use the messages and the hosts defined
    in data/messages.yml and the hosts inventory.

    Parameters
    ----------
    inventory_path : str
        Path to the Ansible hosts inventory
    """
    actual_path = os.path.dirname(os.path.abspath(__file__))
    configure_environment(host_manager)

    host_monitor = HostMonitor(inventory_path=inventory_path,
                               messages_path=os.path.join(actual_path, 'data/messages.yml'),
                               tmp_path=os.path.join(actual_path, 'tmp'))
    host_monitor.run()
