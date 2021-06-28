# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import shutil

import pytest
import yaml
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import set_section_wazuh_conf
import wazuh_testing.tools.configuration as conf


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'decoder_list.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)

# Variables
logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'logtest'))
receiver_sockets_params = [(logtest_path, 'AF_UNIX', 'TCP')]


# Fixtures
@pytest.fixture(scope='function')
def configure_decoders_list(get_configuration, request):
    """
    Configure a custom decoder in local_decoder.xml for testing.
    Restart Wazuh is needed for applying the configuration is optional.
    """

    # configuration for testing
    decode_dir = os.path.join('/var/ossec/',  get_configuration['decoder_dir'])
    if not os.path.exists(decode_dir):
        os.makedirs(decode_dir)

    file_test = os.path.join(test_data_path, get_configuration['decoder_file'])
    file_dst = os.path.join(decode_dir, get_configuration['decoder_file'])

    shutil.copy(file_test, file_dst)

    # Save current configuration
    if 'sections' in get_configuration:
        backup_config = conf.get_wazuh_conf()
        test_config = set_section_wazuh_conf(get_configuration['sections'])
        conf.write_wazuh_conf(test_config)

    yield

    # restore previous configuration
    os.remove(file_dst)
    if len(os.listdir(decode_dir)) == 0:
        os.rmdir(decode_dir)
    # Restore previous configuration
    if 'sections' in get_configuration:
        conf.write_wazuh_conf(backup_config)


@pytest.fixture(scope='module', params=test_cases, ids=[test_case['name'] for test_case in test_cases])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests
def test_decoder_list(get_configuration, configure_decoders_list, connect_to_sockets_function):
    """Check that every test case run on logtest generates the adequate output """

    # send the logtest request
    receiver_sockets[0].send(get_configuration['input'], size=True)

    # receive logtest reply and parse it
    response = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
    result = json.loads(response)

    assert result['error'] == 0
    if 'test_exclude' in get_configuration:
        assert 'name' not in result['data']['output']['decoder']
    else:
        assert result['data']['output']['decoder']['name'] == get_configuration['decoder_name']
