# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.tools.system import HostManager

test_hosts = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'provisioning', 'agentless_cluster', 'inventory.yml')

# Testing credentials
test_user = None
test_passw = None
test_role_id = None
test_policy_id = None

host_manager = HostManager(inventory_path)


@pytest.fixture(scope='module')
def set_role_to_user():
    """Create a relation between the testing user and role/policy."""
    token = host_manager.get_api_token(test_hosts[0])
    response = host_manager.make_api_call(test_hosts[0], method='POST',
                                          endpoint=f'/security/users/{test_user}/roles?role_ids={test_role_id}',
                                          token=token)
    assert response['status'] == 200, f'Failed to set relation between user and role: {response}'


@pytest.mark.parametrize('node1, node2', [
    (test_hosts[0], test_hosts[1]),
    (test_hosts[1], test_hosts[2])
])
def test_change_user_policy_and_role(node1, node2, create_testing_api_user, create_role_and_policy, set_role_to_user):
    """Test that the obtained token is invalid after changing a role or policy related to the user.

    Parameters
    ----------
    node1 : str
        Node from the cluster.
    node2 : str
        Node from the cluster.
    """
    def check_revoked_token(node, current_token):
        # Check that the token was revoked
        resp = host_manager.make_api_call(node, endpoint='/agents', token=current_token)
        assert resp['status'] == 401, f'Token was not revoked: {resp}'

    # Get token with testing user
    token = host_manager.get_api_token(node1, user=test_user, password=test_passw)

    # Check that this user->role->policy relation works
    response = host_manager.make_api_call(node1, endpoint='/agents', token=token)
    assert response['status'] == 200, f'Failed to check relation: {response}'

    # Change policy
    response = host_manager.make_api_call(node1, method='PUT', endpoint=f'/security/policies/{test_policy_id}',
                                          request_body={'name': f'changed_policy_{node1}',
                                                        'policy': {
                                                            'actions': [
                                                                'agents:read'
                                                            ],
                                                            'resources': [
                                                                'agent:id:*'
                                                            ],
                                                            'effect': 'allow'
                                                        }},
                                          token=token)
    assert response['status'] == 200, f'Failed to change policy: {response}'

    check_revoked_token(node1, token)

    # Get another token in other node
    token = host_manager.get_api_token(node2, user=test_user, password=test_passw)

    # Change role in other node
    response = host_manager.make_api_call(node2, method='PUT', endpoint=f'/security/roles/{test_role_id}',
                                          request_body={'name': f'changed_role_{node1}',
                                                        'rule': {
                                                            'MATCH': {
                                                                'definition': 'test'
                                                            }
                                                        }},
                                          token=token)
    assert response['status'] == 200, f'Failed to change role: {response}'

    check_revoked_token(node2, token)
