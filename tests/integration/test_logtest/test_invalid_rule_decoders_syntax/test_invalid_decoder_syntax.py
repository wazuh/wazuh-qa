# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import yaml
import shutil
import json

from wazuh_testing.tools import WAZUH_PATH


# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'invalid_decoder_syntax.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)

# Variables

logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'ossec', 'logtest'))
receiver_sockets_params = [(logtest_path, 'AF_UNIX', 'TCP')]


# Fixtures

@pytest.fixture(scope='function')
def configure_local_decoders(get_configuration, request):
    """
    Configure a custom decoder in local_decoder.xml for testing.
    Restart Wazuh is needed for applying the configuration is optional.
    """

    # save current configuration
    shutil.copy('/var/ossec/etc/decoders/local_decoder.xml', '/var/ossec/etc/decoders/local_decoder.xml.cpy')

    # configuration for testing
    file_test = os.path.join(test_data_path, get_configuration['decoder'])
    shutil.copy(file_test, '/var/ossec/etc/decoders/local_decoder.xml')

    yield

    # restore previous configuration
    shutil.copy('/var/ossec/etc/decoders/local_decoder.xml.cpy', '/var/ossec/etc/decoders/local_decoder.xml')


@pytest.fixture(scope='module', params=test_cases, ids=[test_case['name'] for test_case in test_cases])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

def test_invalid_decoder_syntax(get_configuration, configure_local_decoders, connect_to_sockets_function):
    """Check that every input message in logtest socket generates the adequate output """

    # send the logtest request
    receiver_sockets[0].send(get_configuration['input'], size=True)

    # receive logtest reply and parse it
    response = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
    result = json.loads(response)

    # error list to enable multi-assert per test-case
    errors = []

    if 'output_error' in get_configuration and get_configuration['output_error'] != result["error"]:
        errors.append("output_error")

    if ('output_data_msg' in get_configuration and
            get_configuration['output_data_msg'] not in result["data"]["messages"][0]):
        errors.append("output_data_msg")

    if ('output_data_codemsg' in get_configuration and
            get_configuration['output_data_codemsg'] != result["data"]["codemsg"]):
        errors.append("output_data_codemsg")

    # error if any check fails
    assert not errors, "Failed stage(s) :{}".format("\n".join(errors))
