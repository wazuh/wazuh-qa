# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pytest
from grp import getgrnam
from pwd import getpwnam
from wazuh_testing.api import callback_detect_api_debug
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import check_apply_test, get_api_conf
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.server

# Variables

test_directories = [os.path.join(PREFIX, 'test_logs')]
new_log_file = os.path.join(test_directories[0], 'test.log')
file_monitor = FileMonitor(new_log_file)

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'conf.yaml')
configuration = get_api_conf(configurations_path)


# Fixtures

@pytest.fixture(scope='module', params=configuration)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    # Create the log file with 'ossec' as owner.
    with open(new_log_file, 'w+'):
        pass
    os.chmod(new_log_file, 0o777)
    os.chown(new_log_file, getpwnam("ossec").pw_uid, getgrnam("ossec").gr_gid)


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'logs_info'},
    {'logs_debug'}
])
def test_logs(tags_to_apply, get_configuration, configure_api_environment, restart_api):
    """Check that the logs are saved in the desired path and with desired level.

    Logs are usually store in /var/ossec/logs/api.log and with level "info".
    In this test the api log has a different path and "debug" level configured.
    It checks if logs are saved in the new path and with "debug" level.

    Parameters
    ----------
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Detect any "DEBUG:" message in the new log path
    if get_configuration['configuration']['logs']['level'] == 'info':
        with pytest.raises(TimeoutError):
            file_monitor.start(timeout=15, callback=callback_detect_api_debug,
                               error_message='"DEBUG: ..." event received but not expected.').result()
    else:
        file_monitor.start(timeout=60, callback=callback_detect_api_debug,
                           error_message='Did not receive expected "DEBUG: ..." event')
