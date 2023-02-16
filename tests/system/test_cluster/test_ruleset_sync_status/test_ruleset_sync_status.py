# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import uuid

import pytest
from wazuh_testing.tools import WAZUH_PATH, WAZUH_LOGS_PATH
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager

# Hosts
test_hosts = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
worker_hosts = test_hosts[1:]
pytestmark = [pytest.mark.cluster, pytest.mark.agentless_cluster_env]

# Data paths
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
tmp_path = os.path.join(test_data_path, 'tmp')
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'agentless_cluster', 'inventory.yml')
host_manager = HostManager(inventory_path)
cluster_json_values = [
    {'key': ['intervals', 'worker', 'sync_integrity'], 'value': 120},
    {'key': ['intervals', 'master', 'recalculate_integrity'], 'value': 120},
]

rule_content = f"""
<!-- {str(uuid.uuid4())} -->
<group name="local,syslog,sshd,">
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>
"""


def get_sync_status(api_token):
    """Get ruleset sync status of cluster nodes.

    Args:
        api_token (str): Usable API token.

    Returns:
        list: Dictionaries containing node-name (str) and synced status (bool).
    """
    response = host_manager.make_api_call(host=test_hosts[0], method='GET', token=api_token,
                                          endpoint='/cluster/ruleset/synchronization')
    assert response['status'] == 200, f"Failed when trying to obtain cluster sync status: {response}"
    assert response['json']['data']['total_affected_items'] == len(test_hosts)
    return response['json']['data']['affected_items']


def test_ruleset_sync_status(update_cluster_json):
    """Check if 'GET /cluster/ruleset/synchronization' API endpoint returns correct sync status.

    Verify that, after changing a custom ruleset file in the master node and calling the API endpoint mentioned above,
    the 'synced' status for all worker nodes in the response is False. Wait until an Integrity synchronization
    is run. Now, the response for all workers should be 'synced: True'.
    """
    api_token = host_manager.get_api_token(test_hosts[0])
    for host in test_hosts:
        host_manager.clear_file_without_recreate(host=host, file_path=os.path.join(WAZUH_LOGS_PATH, 'cluster.log'))

    # Check that all workers are synced before starting.
    assert all(item['synced'] for item in get_sync_status(api_token))

    # Modify a custom rule file and verify that synced status is False for all workers.
    host_manager.modify_file_content(host=test_hosts[0],
                                     path=os.path.join(WAZUH_PATH, 'etc', 'rules', 'local_rules.xml'),
                                     content=rule_content)
    assert all(not item['synced'] for item in get_sync_status(api_token) if item['name'] != test_hosts[0])

    # Wait until a Local Integrity task is run in the master and then, Integrity sync tasks are run in the workers.
    HostMonitor(inventory_path=inventory_path, messages_path=os.path.join(test_data_path, 'master_messages.yaml'),
                tmp_path=tmp_path).run()
    HostMonitor(inventory_path=inventory_path, messages_path=os.path.join(test_data_path, 'worker_messages.yaml'),
                tmp_path=tmp_path).run()

    # Verify that synced status is True for all cluster nodes again.
    assert all(item['synced'] for item in get_sync_status(api_token))
