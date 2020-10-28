# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time


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
