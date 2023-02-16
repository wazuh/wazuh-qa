# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from wazuh_testing.tools.system import HostManager

pytestmark = [pytest.mark.agentless_cluster_env]
test_hosts = ['wazuh-master', 'wazuh-worker1']
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'provisioning', 'agentless_cluster', 'inventory.yml')
default_api_conf = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'api_configurations', 'default.yaml')

# Testing credentials
test_user = None
test_user_id = None
test_passw = None

host_manager = HostManager(inventory_path)


@pytest.mark.parametrize('login_endpoint, host, old_password, new_password', [
    # User-roles based login
    ({}, 'wazuh-master', test_passw, 'Newpass1*'),
    ({}, 'wazuh-worker1', 'Newpass1*', 'Newpass2*'),
    # Auth context login
    ({"auth_context": {"username": "testing"}}, 'wazuh-master', 'Newpass2*', 'Newpass1*'),
    ({"auth_context": {"username": "testing"}}, 'wazuh-worker1', 'Newpass1*', 'Newpass2*')
])
def test_update_password(login_endpoint, host, old_password, new_password, set_default_api_conf,
                         create_testing_api_user,
                         create_security_resources):
    """Test that the obtained token is invalid after updating the password from its user.

    Parameters
    ----------
    host : str
        Host where the test will be run.
    old_password : str
        Password before updating.
    new_password : str
        New password to update to.
    """
    # Get token
    token = host_manager.get_api_token(host, user=test_user, password=test_passw if not old_password else old_password,
                                       **login_endpoint)

    # Update password
    response = host_manager.make_api_call(host, method='PUT', endpoint=f'/security/users/{test_user_id}',
                                          request_body={'password': new_password}, token=token)
    assert response['status'] == 200, f'Failed to change password: {response}'

    # Try to make another call with the same token
    response = host_manager.make_api_call(host, endpoint='/agents', token=token)
    assert response['status'] == 401, f'Token was not revoked: {response}'
