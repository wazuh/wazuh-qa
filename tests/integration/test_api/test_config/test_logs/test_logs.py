'''
copyright:
    Copyright (C) 2015-2021, Wazuh Inc.

    Created by Wazuh, Inc. <info@wazuh.com>.

    This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type:
    integration

description:
    These tests will check if the `level` setting of the API is working properly.
    This setting allows specifying the level of detail (INFO, DEBUG)
    of the messages written to the `api.log` file.

tiers:
    - 0

component:
    manager

path:
    tests/integration/test_api/test_config/test_logs/

daemons:
    - apid
    - analysisd
    - syscheckd
    - wazuh-db

os_support:
    - linux, centos 6
    - linux, centos 7
    - linux, centos 8
    - linux, rhel6
    - linux, rhel7
    - linux, rhel8
    - linux, amazon linux 1
    - linux, amazon linux 2
    - linux, debian buster
    - linux, debian stretch
    - linux, debian wheezy
    - linux, ubuntu bionic
    - linux, ubuntu xenial
    - linux, ubuntu trusty
    - linux, arch linux

coverage:

pytest_args:

tags:
    - api
'''
import os
from grp import getgrnam
from pwd import getpwnam

import pytest
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
    # Create the log file with 'wazuh' as owner.
    with open(new_log_file, 'w+'):
        pass
    os.chmod(new_log_file, 0o777)
    os.chown(new_log_file, getpwnam("wazuh").pw_uid, getgrnam("wazuh").gr_gid)


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'logs_info'},
    {'logs_debug'}
])
def test_logs(tags_to_apply, get_configuration, configure_api_environment, restart_api):
    '''
    description:
        Check that the logs are saved in the desired path and with desired level.
        Logs are usually store in `/var/ossec/logs/api.log` and with level `info`.
        In this test the API log has a different path and `debug` level configured.
        It checks if logs are saved in the new path and with `debug` level.

    wazuh_min_version:
        3.13

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.

        - get_configuration:
            type: fixture
            brief: Get configurations from the module.

        - configure_api_environment:
            type: fixture
            brief: Configure a custom environment for API testing.

        - restart_api:
            type: fixture
            brief: Reset `api.log` and start a new monitor.

    assertions:
        - Verify that no `DEBUG` messages are written when the value of the `level` setting is set to `info`.
        - Verify that `DEBUG` messages are written when the value of the `level` setting is set to `debug`.

    test_input:
        Different test cases are contained in an external `YAML` file (conf.yaml)
        which includes API configuration parameters.

    logging:
        - api.log:
            - r".*DEBUG: (.*)"

    tags:

    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Detect any "DEBUG:" message in the new log path
    if get_configuration['configuration']['logs']['level'] == 'info':
        with pytest.raises(TimeoutError):
            file_monitor.start(timeout=15, callback=callback_detect_api_debug,
                               error_message='"DEBUG: ..." event received but not expected.').result()
    else:
        file_monitor.start(timeout=60, callback=callback_detect_api_debug,
                           error_message='Did not receive expected "DEBUG: ..." event')
