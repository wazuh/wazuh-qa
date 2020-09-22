# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH

# Hosts
testinfra_hosts = ["wazuh-master", "wazuh-worker1", "wazuh-agent1"]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'enrollment_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = os.path.join(local_path, 'data/messages.yml')
tmp_path = os.path.join(local_path, 'tmp')

@pytest.fixture(scope='module')
def configure_environment():
    host_manager.get_host('wazuh-master').ansible('command', f'service wazuh-manager stop', check=False)
    host_manager.get_host('wazuh-worker1').ansible('command', f'service wazuh-manager stop', check=False)
    host_manager.clear_file(host='wazuh-master',  file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))
    host_manager.clear_file(host='wazuh-worker1', file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))
    yield


def test_agent_info_sync(configure_environment):
    """Check agent agent-info synchronization works as expected."""

    host_manager.control_service(host='wazuh-master', service='wazuh', state="started")
    host_manager.control_service(host='wazuh-worker1', service='wazuh', state="started")

    # Run the callback checks for the cluster.log
    HostMonitor(inventory_path=inventory_path,
                messages_path=messages_path,
                tmp_path=tmp_path).run()

