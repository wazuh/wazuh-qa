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
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
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
import tempfile

import pytest
from test_fim.test_files.test_report_changes.common import translate_size
from wazuh_testing.fim import LOG_FILE_PATH, callback_disk_quota_limit_reached, generate_params
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import remove_file, random_string, write_file
from wazuh_testing.tools.monitoring import FileMonitor

# Marks
pytestmark = [pytest.mark.tier(level=1)]

# Variables
extended_timeout = 30
compression_ratio = 12
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
temp_dir = tempfile.gettempdir()

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_disk_quota_values_conf.yaml')


# Configurations
disk_quota_values = ['1KB', '100KB', '1MB', '10MB']

parameters = [
    {'TEST_DIRECTORIES': temp_dir,
     'DISK_QUOTA_LIMIT': disk_quota_elem} for disk_quota_elem in disk_quota_values
]

metadata = [
    {'test_directories': temp_dir,
     'disk_quota_limit': disk_quota_elem} for disk_quota_elem in disk_quota_values
]

configuration_ids = [f"disk_quota_limit_{x['disk_quota_limit']}" for x in metadata]

configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


# Fixtures
@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


@pytest.fixture(scope='function')
def create_specific_size_file(get_configuration, request):
    """Create a file with a specific size requested from test configuration"""
    test_file = os.path.join(temp_dir, 'test')

    # Translate given size from string to number in bytes
    translated_size = translate_size(configured_size=get_configuration['metadata']['disk_quota_limit'])
    write_file(test_file, random_string(translated_size*compression_ratio))

    yield

    remove_file(test_file)


# Tests
@pytest.mark.skip(reason="It will be blocked by #1602, when it was solve we can enable again this test")
def test_disk_quota_values(get_configuration, configure_environment, create_specific_size_file, restart_syscheckd):
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
    wazuh_log_monitor.start(timeout=extended_timeout, callback=callback_disk_quota_limit_reached,
                            error_message='Did not receive expected '
                                          '"The maximum configured size for the ... folder has been reached, ..." event.')
