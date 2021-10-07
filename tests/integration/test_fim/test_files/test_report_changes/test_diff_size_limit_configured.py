'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM limits the size of
       'diff' information to generate from the file monitored when the 'diff_size_limit' and
       the 'report_changes' options are enabled.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

tier: 1

modules:
    - fim

components:
    - agent
    - manager

daemons:
    - wazuh-syscheckd

os_platform:
    - linux
    - windows

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6
    - Windows 10
    - Windows 8
    - Windows 7
    - Windows Server 2016
    - Windows server 2012
    - Windows server 2003
    - Windows XP

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#directories

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_report_changes
'''
import os

import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_diff_size_limit_value, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.tier(level=1)]

# Variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1')]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]
DIFF_LIMIT_VALUE = 2

# Configurations

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'DIFF_SIZE_LIMIT': {'diff_size_limit': '2kb'},
                                                           'TEST_DIRECTORIES': directory_str,
                                                           'FILE_SIZE_ENABLED': 'yes',
                                                           'FILE_SIZE_LIMIT': '1GB',
                                                           'DISK_QUOTA_ENABLED': 'no',
                                                           'DISK_QUOTA_LIMIT': '2KB',
                                                           'MODULE_NAME': __name__})

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf_diff_size_limit'}
])
def test_diff_size_limit_default(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    '''
    description: Check if the 'wazuh-syscheckd' daemon limits the size of 'diff' information to generate from
                 the value set in the 'diff_size_limit' attribute when the global 'file_size' tag is different.
                 For this purpose, the test will monitor a directory and, once the FIM is started, it will wait
                 for the FIM event related to the maximum file size to generate 'diff' information. Finally,
                 the test will verify that the value gotten from that FIM event corresponds with the one set
                 in the 'diff_size_limit'.

    wazuh_min_version: 4.2.0

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if matches with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that an FIM event is generated indicating the size limit of 'diff' information to generate
          set in the 'diff_size_limit' attribute when the global 'file_size' tag is different.

    input_description: A test case (ossec_conf_diff_size_limit) is contained in external YAML
                       file (wazuh_conf.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon and, these are combined with the
                       testing directory to be monitored defined in the module.

    expected_output:
        - r'.*Maximum file size limit to generate diff information configured to'

    tags:
        - diff
        - scheduled
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    diff_size_value = wazuh_log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=callback_diff_size_limit_value,
        error_message='Did not receive expected "Maximum file size limit configured to \'... KB\'..." event').result()

    if diff_size_value:
        assert diff_size_value == str(DIFF_LIMIT_VALUE), 'Wrong value for diff_size_limit'
    else:
        raise AssertionError('Wrong value for diff_size_limit')
