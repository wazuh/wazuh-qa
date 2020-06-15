# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest

from wazuh_testing.tools.system import HostManager

test_hosts = ['wazuh-master', 'wazuh-worker1', 'wazuh-worker2']
inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              'provisioning', 'agentless_cluster', 'inventory.yml')


host_manager = HostManager(inventory_path)


@pytest.mark.parametrize('revoke_host', test_hosts)
def test_revoke_all_tokens_with_api(revoke_host):
    """Test that every token gets revoked after making an API call to 'PUT /security/user/revoke'.

    Parameters
    ----------
    host : str
        Host where the test will be run.
    """
    def default_api_call(token_dikt, expected_code=200):
        for host, token in token_dikt.items():
            response = host_manager.make_api_call(host, endpoint='/agents', token=token)
            assert response['status'] == expected_code, f'API call failed. Response: {response}'

    # Get valid tokens
    tokens = {host: host_manager.get_api_token(host) for host in test_hosts}

    # Make an API call with each token and assert we have permissions
    default_api_call(tokens)

    # Invalid all tokens from one node
    host_manager.make_api_call(revoke_host, method='PUT', endpoint='/security/user/revoke',
                               token=tokens[revoke_host])

    # Assert our tokens are invalid now
    default_api_call(tokens, expected_code=401)

