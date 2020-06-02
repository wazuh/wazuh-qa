# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import time

import pytest

from wazuh_testing.tools.system import HostManager

test_hosts = ["wazuh-master", "wazuh-worker1"]
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'provisioning', 'agentless_cluster', 'inventory.yml')

# Testing credentials
test_user = None
test_passw = None

host_manager = HostManager(inventory_path)


@pytest.mark.parametrize('host, old_password, new_password', [
    ('wazuh-master', test_passw, 'Newpass1*'),
    ('wazuh-worker1', 'Newpass1*', 'Newpass2*')
])
def test_update_password(host, old_password, new_password, create_testing_api_user):
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
    token = host_manager.get_api_token(host, user=test_user,
                                       password=test_passw if not old_password else old_password)

    # Update password
    response = host_manager.make_api_call(host, method='PUT', endpoint=f'/security/users/{test_user}',
                                          request_body={'password': new_password}, token=token)
    assert response['status'] == 200, f'Failed to change password: {response}'

    # Try to make another call with the same token
    response = host_manager.make_api_call(host, endpoint='/agents', token=token)
    assert response['status'] == 401, f'Token was not revoked: {response}'
