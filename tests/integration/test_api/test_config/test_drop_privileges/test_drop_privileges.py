# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import pwd
import pytest
from wazuh_testing.tools.configuration import check_apply_test, get_api_conf
from wazuh_testing.tools.services import get_process_cmd

# Marks

pytestmark = pytest.mark.server

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'conf.yaml')
configuration = get_api_conf(configurations_path)


# Fixtures

@pytest.fixture(scope='module', params=configuration)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'drop_privileges_enabled'},
    {'drop_privileges_disabled'},
])
def test_drop_privileges(tags_to_apply, get_configuration, configure_api_environment,
                         restart_api, wait_for_start, get_api_details):
    """Check if drop_privileges affects the user of the API process.

    In this test, the PID of the API process is obtained. After that,
    it gets the user (root or ossec) and checks if it matches the
    drop_privileges setting.

    Parameters
    ----------
    tags_to_apply : set
        Run test if match with a configuration identifier, skip otherwise.
    """
    check_apply_test(tags_to_apply, get_configuration['tags'])
    drop_privileges = get_configuration['configuration']['drop_privileges']

    # Get wazuh-apid process info
    api_process = get_process_cmd('/api/scripts/wazuh-apid.py')
    if not api_process:
        pytest.fail("The process '/api/scripts/wazuh-apid.py' could not be found")

    # Get current user of the process
    proc_stat_file = os.stat("/proc/%d" % api_process.pid)
    uid = proc_stat_file.st_uid
    username = pwd.getpwuid(uid)[0]

    if drop_privileges:
        assert username == 'ossec', f'Expected user was "ossec", but the real one is {username}'
    else:
        assert username == 'root', f'Expected user was "root", but the real one is {username}'
