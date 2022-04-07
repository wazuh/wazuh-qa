'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The RIDS(Remote Identifiers) are the agent-manager remoted messages counter. Each message is identified by the
       next possible number(identifier). Only the incoming messages with a valid RID(higher than previous) are allowed.
       This functionality has a closing time value, which allows removing an agent's file handler when it does not send
       a message during a period of time(five minutes by default).

components:
    - rids

targets:
    - manager

daemons:
    - wazuh-remoted
    - wazuh-agentd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://github.com/wazuh/wazuh/blob/master/src/os_crypto/shared/msgs.c
    - https://documentation.wazuh.com/current/user-manual/reference/internal-options.html#remoted
    - https://github.com/wazuh/wazuh/blob/master/src/config/remote-config.c
    - https://github.com/wazuh/wazuh/pull/459
    - https://github.com/wazuh/wazuh/pull/7746
    - https://github.com/wazuh/wazuh/issues/6112

tags:
    - rids
'''
import os

import pytest
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.services import control_service

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

metadata = [
    {
        'remoted.verify_msg_id': 1,
        'remoted.worker_pool': 4,
        'expected_start': False
    },
    {
        'remoted.verify_msg_id': 1,
        'remoted.worker_pool': 1,
        'expected_start': True
    },
    {
        'remoted.verify_msg_id': 0,
        'remoted.worker_pool': 4,
        'expected_start': True
    }
]
params = [{} for x in range(0, len(metadata))]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                              'data')
configurations_path = os.path.join(test_data_path, 'wazuh_manager_conf.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__,
                                           params=params, metadata=metadata)


@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


def restart_service():
    control_service('restart')


def set_internal_options_conf(param, value):
    new_content = ''

    internal_options = os.path.join(WAZUH_PATH, 'etc', 'internal_options.conf')

    with open(internal_options, 'r') as f:
        lines = f.readlines()

        for line in lines:
            new_line = line
            if param in line:
                new_line = f'{param}={value}\n'
            new_content += new_line

    with open(internal_options, 'w') as f:
        f.write(new_content)


def test_rids_conf(get_configuration, configure_environment):
    '''
    description: Check that RIDS configuration works as expected for the following fields, `remoted.verify_msg_id` and
                 `remoted.worker_pool`. To do this, it modifies the local internal options with the test case metadata
                 and restarts Wazuh to verify that the daemon starts or not. Finally, when a correct configuration has
                 been tested, it restores the `internal_options.conf` as it was before running the test.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configuration from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.

    assertions:
        - Verify that the RIDS configuration is applied correctly(or not).

    input_description: Some metadata is defined in the module. These include some configurations stored in
                       the 'wazuh_manager_conf.yaml'.

    expected_output:
        - The `expected_start` boolean variable with `True` when a defined valid RIDS configuration is loaded.
        - The `expected_start` boolean variable with `False` when a defined wrong RIDS configuration is loaded.
    '''
    metadata = get_configuration.get('metadata')
    expected_start = metadata['expected_start']

    set_internal_options_conf('remoted.verify_msg_id', metadata['remoted.verify_msg_id'])
    set_internal_options_conf('remoted.worker_pool', metadata['remoted.worker_pool'])

    try:
        restart_service()
        assert expected_start, 'Expected configuration error'
    except ValueError:
        assert not expected_start, 'Start error was not expected'

    # Set default config again
    set_internal_options_conf('remoted.verify_msg_id', 0)
    set_internal_options_conf('remoted.worker_pool', 4)
