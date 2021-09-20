# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import shutil

import pytest
import yaml
from wazuh_testing.tools.configuration import set_section_wazuh_conf, get_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools import WAZUH_PATH, LOGTEST_SOCKET_PATH, LOG_FILE_PATH
from wazuh_testing.logtest import callback_logtest_started
from wazuh_testing.tools.services import control_service
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools.file import truncate_file


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
messages_path = os.path.join(test_data_path, 'log_alert_level.yaml')
logtest_startup_timeout = 30

with open(messages_path) as f:
    test_cases = yaml.safe_load(f)

# Variables
receiver_sockets_params = [(LOGTEST_SOCKET_PATH, 'AF_UNIX', 'TCP')]
receiver_sockets = None


# Fixtures
@pytest.fixture(scope='function')
def configure_rules_list(get_configuration, request):
    """Configure a custom rules and log alert level for testing.
    Restart Wazuh is not needed for applying the configuration is optional.
    """

    # configuration for testing
    rules_dir = os.path.join(WAZUH_PATH, get_configuration['rule_dir'])
    if not os.path.exists(rules_dir):
        os.makedirs(rules_dir)

    file_test = os.path.join(test_data_path, get_configuration['rule_file'])
    file_dst = os.path.join(rules_dir, get_configuration['rule_file'])

    shutil.copy(file_test, file_dst)

    yield

    # restore previous configuration
    os.remove(file_dst)
    if len(os.listdir(rules_dir)) == 0:
        os.rmdir(rules_dir)


@pytest.fixture(scope='module')
def wait_for_logtest_startup(request):
    """Wait until logtest has begun."""
    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=logtest_startup_timeout, callback=callback_logtest_started)


@pytest.fixture(scope='module')
def restart_required_logtest_daemons():
    """Wazuh logtests daemons handler."""
    required_logtest_daemons = ['wazuh-analysisd']

    truncate_file(LOG_FILE_PATH)

    for daemon in required_logtest_daemons:
        control_service('restart', daemon=daemon)

    yield

    for daemon in required_logtest_daemons:
        control_service('stop', daemon=daemon)


@pytest.fixture(scope='module', params=test_cases, ids=[test_case['name'] for test_case in test_cases])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests
def test_rule_list(restart_required_logtest_daemons, get_configuration,
                   configure_environment, configure_rules_list,
                   wait_for_logtest_startup, connect_to_sockets_function):
    """Check that every test case run on logtest generates the adequate output."""

    # send the logtest request
    receiver_sockets[0].send(get_configuration['input'], size=True)

    # receive logtest reply and parse it
    response = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
    result = json.loads(response)

    assert result['error'] == 0
    assert result['data']['output']['rule']['id'] == get_configuration['rule_id']
    assert result['data']['alert'] is get_configuration['alert']
