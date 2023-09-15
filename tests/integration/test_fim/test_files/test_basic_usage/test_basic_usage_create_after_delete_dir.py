'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. In particular, these tests will check if FIM events are still generated when
       a monitored directory is deleted and created again.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

components:
    - fim

suite: files_basic_usage

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim_basic_usage
'''
import os
import shutil
import sys
import time

import pytest
from wazuh_testing import T_10
from wazuh_testing.modules.fim.utils import generate_params, regular_file_cud
from wazuh_testing.tools import PREFIX, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = [pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables

directory_str = os.path.join(PREFIX, 'testdir1')
test_directories = [directory_str]
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path,
                                   'wazuh_conf.yaml' if sys.platform != 'win32' else 'wazuh_conf_win32.yaml')
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
mark_skip_agentWindows = pytest.mark.skipif(sys.platform == 'win32', reason="It will be blocked by wazuh/wazuh-qa#2174")

# Configurations
windows_audit_interval = 1
conf_params = {'TEST_DIRECTORIES': directory_str, 'MODULE_NAME': __name__,
               'WINDOWS_AUDIT_INTERVAL': str(windows_audit_interval)}
p, m = generate_params(extra_params=conf_params, modes=['realtime', 'whodata'])
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)


# Fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests

@pytest.mark.parametrize('tags_to_apply', [
    {'ossec_conf'}
])
@mark_skip_agentWindows
def test_create_after_delete(tags_to_apply, get_configuration, configure_environment, restart_syscheckd,
                             wait_for_fim_start):
    '''
    description: Check if a monitored directory keeps reporting FIM events after deleting and creating it again.
                 Under Windows systems, it verifies that the directory watcher is refreshed (checks the SACLs)
                 after directory re-creation one second after. For this purpose, the test creates the testing
                 directory to be monitored, checks that FIM events are generated, and then deletes it.
                 Finally, it creates the directory again and verifies that the events are still generated correctly.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - tags_to_apply:
            type: set
            brief: Run test if match with a configuration identifier, skip otherwise.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_syscheckd:
            type: fixture
            brief: Clear the 'ossec.log' file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that FIM events are still generated when a monitored directory is deleted and created again.

    input_description: A test case (ossec_conf) is contained in external YAML file
                       (wazuh_conf.yaml or wazuh_conf_win32.yaml) which includes configuration
                       settings for the 'wazuh-syscheckd' daemon and, it is combined with
                       the testing directories to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (Initial scan when restarting Wazuh)
        - Multiple FIM events logs of the monitored directories.

    tags:
        - realtime
        - who_data
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])

    # Create the monitored directory with files and check that events are not raised
    regular_file_cud(directory_str, wazuh_log_monitor, file_list=['file1', 'file2', 'file3'],
                     min_timeout=T_10, triggers_event=True)

    # Delete the directory
    os.rename(directory_str, f'{directory_str}_delete')
    shutil.rmtree(f'{directory_str}_delete', ignore_errors=True)
    time.sleep(5)

    # Re-create the directory
    os.makedirs(directory_str, exist_ok=True, mode=0o777)
    time.sleep(5)

    # Assert that events of new CUD actions are raised after next scheduled scan
    regular_file_cud(directory_str, wazuh_log_monitor, file_list=['file4', 'file5', 'file6'],
                     min_timeout=T_10, triggers_event=True)
