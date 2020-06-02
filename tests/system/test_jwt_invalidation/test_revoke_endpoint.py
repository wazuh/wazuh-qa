# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.tools.system import HostManager

test_hosts = ["wazuh-master", "wazuh-worker1", "wazuh-worker2"]
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'provisioning', 'agentless_cluster', 'inventory.yml')


host_manager = HostManager(inventory_path)


@pytest.mark.parametrize('host', test_hosts)
def test_revoke_all_tokens_with_api(host):
    """Test that every token gets revoked after making an API call to 'PUT /security/user/revoke'.

    Parameters
    ----------
    host : str
        Host where the test will be run.
    """
    def default_api_call(t_list, expected_code=200):
        for token in t_list:
            response = host_manager.make_api_call(host, endpoint='/agents', token=token)
            assert response['status'] == expected_code, f'API call failed. Response: {response}'

    # Get valid tokens
    n_tokens = 2
    token_list = [host_manager.get_api_token(host) for _ in range(n_tokens)]

    # Make an API call with each token and assert we have permissions. Default endpoint is 'GET /'
    default_api_call(token_list)

    # Invalid all tokens
    host_manager.make_api_call(host, method='PUT', endpoint='/security/user/revoke', token=token_list[0])

    # Assert our tokens are invalid now
    default_api_call(token_list, expected_code=401)

