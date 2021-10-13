# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os

from wazuh_testing.tools import WAZUH_PATH
from yaml import safe_load
from shutil import copy
from json import loads

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'invalid_decoder_syntax.yaml')
with open(messages_path) as f:
    test_cases = safe_load(f)

# Variables

logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'logtest'))
receiver_sockets_params = [(logtest_path, 'AF_UNIX', 'TCP')]


# Fixtures

@pytest.fixture(scope='function')
def configure_local_decoders(get_configuration):
    """Configure a custom decoder for testing."""

    # configuration for testing
    file_test = os.path.join(test_data_path, get_configuration['decoder'])
    target_file_test = os.path.join(WAZUH_PATH, 'etc', 'decoders', get_configuration['decoder'])

    copy(file_test, target_file_test)

    yield

    # restore previous configuration
    os.remove(target_file_test)


@pytest.fixture(scope='module', params=test_cases, ids=[test_case['name'] for test_case in test_cases])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests
def test_invalid_decoder_syntax(get_configuration, configure_local_decoders,
                                restart_required_logtest_daemons,
                                wait_for_logtest_startup,
                                connect_to_sockets_function):
    """Check that every input message in logtest socket generates the adequate output."""

    # send the logtest request
    receiver_sockets[0].send(get_configuration['input'], size=True)

    # receive logtest reply and parse it
    response = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
    result = loads(response)

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
