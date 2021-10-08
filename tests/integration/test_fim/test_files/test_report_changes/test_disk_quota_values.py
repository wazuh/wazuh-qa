'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will check if FIM limits the size of
       the 'queue/diff/local' folder where Wazuh stores the compressed files used to perform
       the 'diff' operation when the 'disk_quota' limit is set.
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
    - macos
    - solaris

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
    - macOS Catalina
    - Solaris 10
    - Solaris 11

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
import sys

import pytest
from test_fim.test_files.test_report_changes.common import disable_file_max_size, restore_file_max_size
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, callback_disk_quota_limit_reached, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.tier(level=1)]

# Variables

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

if sys.platform == 'linux':
    test_dirs = ['/etc']
elif sys.platform == 'win32':
    test_dirs = [os.path.join("C:", os.sep, "Program Files (x86)")]
elif sys.platform == 'darwin':
    test_dirs = ['/Applications']
elif sys.platform == 'sunos5':
    test_dirs = ['/etc']
else:
    test_dirs = [os.path.join(PREFIX, 'testdir1')]

directory_str = ','.join(test_dirs)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_dirs[0]

# Configurations

disk_quota_values = ['1KB', '100KB', '1MB', '10MB']

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'TEST_DIRECTORIES': directory_str,
                                                           'FILE_SIZE_ENABLED': 'no',
                                                           'FILE_SIZE_LIMIT': '10MB',
                                                           'DISK_QUOTA_ENABLED': 'yes',
                                                           'MODULE_NAME': __name__},
                                             apply_to_all=({'DISK_QUOTA_LIMIT': disk_quota_elem}
                                                           for disk_quota_elem in disk_quota_values))

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Functions

def extra_configuration_before_yield():
    """
    Disable syscheck.file_max_size internal option
    """
    disable_file_max_size()


def extra_configuration_after_yield():
    """
    Restore syscheck.file_max_size internal option
    """
    restore_file_max_size()


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf_diff'}
])
def test_disk_quota_values(tags_to_apply, get_configuration, configure_environment, restart_syscheckd):
    '''
    description: Check if the 'wazuh-syscheckd' daemon limits the size of the folder where the data
                 used to perform the 'diff' operations is stored when the 'disk_quota' limit is set.
                 For this purpose, the test will monitor a system directory with lot of files changes
                 that when compressed, are larger than the configured 'disk_quota' limit. Finally, once
                 the FIM is started, the test will verify that the FIM event related to the reached
                 disk quota has been generated.

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
        - Verify that FIM events are generated indicating the disk quota exceeded for monitored files
          when the 'disk_quota' option is enabled.

    input_description: A test case (ossec_conf_diff) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these
                       are combined with the 'disk_quota' values defined in the module.

    expected_output:
        - r'.*The (.*) of the file size .* exceeds the disk_quota.*'

    tags:
        - disk_quota
        - scheduled
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    wazuh_log_monitor.start(
        timeout=global_parameters.default_timeout * 25,
        callback=callback_disk_quota_limit_reached,
        error_message='Did not receive expected '
                      '"The maximum configured size for the ... folder has been reached, ..." event.'
                      )
