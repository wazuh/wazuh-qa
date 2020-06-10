# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
import yaml
from wazuh_testing.tools.system import HostManager
from wazuh_testing.tools import WAZUH_SECURITY_CONF

test_hosts = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'provisioning', 'agentless_cluster', 'inventory.yml')

host_manager = HostManager(inventory_path)
opposite_rbac_mode = {'white': 'black', 'black': 'white'}


@pytest.fixture(scope='module')
def restore_default_security_settings():
    yield

    token = host_manager.get_api_token('wazuh-master')
    response = host_manager.make_api_call('wazuh-master', method='DELETE', endpoint='/security/config', token=token)
    assert response['status'] == 200, f'Failed to restore default security settings: {response}'


def test_change_rbac_mode_with_endpoint(restore_default_security_settings):
    """Check that all tokens are revoked when changing RBAC mode with the security endpoint."""
    # Get valid tokens
    tokens = {host: host_manager.get_api_token(host) for host in test_hosts}

    # Get current RBAC mode
    response = host_manager.make_api_call(test_hosts[0], endpoint='/security/config', token=tokens[test_hosts[0]])
    assert response['status'] == 200, f'Failed to get security settings: {response}'
    new_rbac_mode = opposite_rbac_mode[response['json']['rbac_mode']]

    # Change RBAC mode using endpoint
    response = host_manager.make_api_call(test_hosts[0], method='PUT', endpoint='/security/config',
                                          request_body={'rbac_mode': new_rbac_mode}, token=tokens[test_hosts[0]])
    assert response['status'] == 200, f'Failed to change security settings: {response}'

    # Assert every token is revoked
    for host in test_hosts:
        response = host_manager.make_api_call(host, endpoint='/agents', token=tokens[host])
        assert response['status'] == 401, f'Token was not revoked on node {host}: {response}'


def test_change_rbac_mode_manually(restore_default_security_settings):
    """Check that all tokens are revoked when changing RBAC mode manually in the security.yaml ."""
    # Get valid tokens
    tokens = {host: host_manager.get_api_token(host) for host in test_hosts}

    # Get current RBAC mode
    response = host_manager.make_api_call(test_hosts[0], endpoint='/security/config', token=tokens[test_hosts[0]])
    assert response['status'] == 200, f'Failed to get security settings: {response}'
    new_rbac_mode = opposite_rbac_mode[response['json']['rbac_mode']]

    # Change RBAC mode manually
    host_manager.modify_file_content(test_hosts[0], path=WAZUH_SECURITY_CONF,
                                     content=yaml.safe_dump({'rbac_mode': new_rbac_mode}))

    # Assert every token is revoked
    for host in test_hosts:
        response = host_manager.make_api_call(host, endpoint='/agents', token=tokens[host])
        assert response['status'] == 401, f'Token was not revoked on node {host}: {response}'
