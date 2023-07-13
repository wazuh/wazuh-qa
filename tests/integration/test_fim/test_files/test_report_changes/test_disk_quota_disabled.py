'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when
       these files are modified. Specifically, these tests will verify that FIM does not limit
       the size of the 'queue/diff/local' folder where Wazuh stores the compressed files used
       to perform the 'diff' operation when the 'disk_quota' option is disabled.
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
from wazuh_testing import global_parameters, LOG_FILE_PATH, REGULAR
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.fim import FIM_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options
from wazuh_testing.modules.fim.event_monitor import callback_disk_quota_limit_reached
from wazuh_testing.modules.fim.utils import generate_params, create_file
from test_fim.common import generate_string

# Marks

pytestmark = [pytest.mark.tier(level=1)]

# Variables
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_directories = [os.path.join(PREFIX, 'testdir1')]
directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]

# Configurations

conf_params, conf_metadata = generate_params(extra_params={'REPORT_CHANGES': {'report_changes': 'yes'},
                                                           'TEST_DIRECTORIES': directory_str,
                                                           'FILE_SIZE_ENABLED': 'no',
                                                           'FILE_SIZE_LIMIT': '1KB',
                                                           'DISK_QUOTA_ENABLED': 'no',
                                                           'DISK_QUOTA_LIMIT': '2KB'})

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests
@pytest.mark.parametrize('filename, folder, size', [('regular_0', testdir1, 10000000)])
def test_disk_quota_disabled(filename, folder, size, get_configuration, configure_environment,
                             configure_local_internal_options_module, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the 'wazuh-syscheckd' daemon limits the size of the folder where the data used
                 to perform the 'diff' operations is stored when the 'disk_quota' option is disabled.
                 For this purpose, the test will monitor a directory and, once the FIM is started, it
                 will create a testing file that, when compressed, is larger than the configured
                 'disk_quota' limit. Finally, the test will verify that the FIM event related
                 to the reached disk quota has not been generated.

    wazuh_min_version: 4.6.0

    tier: 1

    parameters:
        - filename:
            type: str
            brief: Name of the testing file to be created.
        - folder:
            type: str
            brief: Path to the directory where the testing files are being created.
        - size:
            type: int
            brief: Size of each testing file in bytes.
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
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that no FIM events are generated indicating the disk quota exceeded for monitored files
          when the 'disk_quota' option is disabled.

    input_description: A test case (ossec_conf_diff) is contained in external YAML file (wazuh_conf.yaml)
                       which includes configuration settings for the 'wazuh-syscheckd' daemon and, these
                       are combined with the testing directory to be monitored defined in the module.

    expected_output:
        - r'.*The (.*) of the file size .* exceeds the disk_quota.*' (if the test fails)

    tags:
        - disk_quota
        - scheduled
    '''
    to_write = generate_string(size, '0')
    create_file(REGULAR, folder, filename, content=to_write)

    with pytest.raises(TimeoutError):
        wazuh_log_monitor.start(timeout=global_parameters.default_timeout, callback=callback_disk_quota_limit_reached)
