'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM limits the size of
       the 'queue/diff/local' folder, where Wazuh stores the compressed files used to perform
       the 'diff' operation, to the default value when the 'report_changes' option is enabled.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured
       files for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_report_changes

targets:
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
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html#disk-quota

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
from wazuh_testing import global_parameters, LOG_FILE_PATH
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor, generate_monitoring_callback
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import CB_DISK_QUOTA_LIMIT_CONFIGURED_VALUE, ERR_MSG_DISK_QUOTA_LIMIT
from wazuh_testing.modules.fim.utils import generate_params


# Marks

pytestmark = [pytest.mark.tier(level=1)]

# Variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1')]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]
DEFAULT_SIZE = 1 * 1024 * 1024

# Configurations

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'TEST_DIRECTORIES': directory_str})

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

def test_disk_quota_default(get_configuration, configure_environment,
                            configure_local_internal_options_module, restart_syscheckd):
    '''
    description: Check if the 'wazuh-syscheckd' daemon limits the size of the folder where the data used to perform
                 the 'diff' operations is stored to the default value. For this purpose, the test will monitor
                 a directory and, once the FIM is started, it will wait for the FIM event related to the maximum
                 disk quota to store 'diff' information. Finally, the test will verify that the value gotten from
                 that FIM event corresponds with the default value of the 'disk_quota' tag (1GB).

    wazuh_min_version: 4.6.0

    tier: 1

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.

    assertions:
        - Verify that an FIM event is generated indicating the size limit of the folder
          to store 'diff' information to the default limit of the 'disk_quota' tag (1GB).

    input_description: A test case (ossec_conf_diff_default) is contained in external YAML
                       file (wazuh_conf.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon and, these are combined with the
                       testing directory to be monitored defined in the module.

    expected_output:
        - r'.*Maximum disk quota size limit configured to'

    tags:
        - disk_quota
        - scheduled
    '''

    disk_quota_value = wazuh_log_monitor.start(
        timeout=global_parameters.default_timeout,
        callback=generate_monitoring_callback(CB_DISK_QUOTA_LIMIT_CONFIGURED_VALUE),
        error_message=ERR_MSG_DISK_QUOTA_LIMIT).result()

    if disk_quota_value:
        assert disk_quota_value == str(DEFAULT_SIZE), 'Wrong value for disk_quota'
    else:
        raise AssertionError('Wrong value for disk_quota')
