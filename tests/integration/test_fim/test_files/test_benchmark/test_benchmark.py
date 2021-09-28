'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the File Integrity Monitoring (`FIM`) system watches selected
       files and triggering alerts when these files are modified. Specifically, they will check
       if `FIM` CUD events are generated for each modified file before the specified time expires.
       The `FIM` capability is managed by the `wazuh-syscheckd` daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

tier: 0

modules:
    - fim

components:
    - agent
    - manager

daemons:
    - wazuh-agentd
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

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the `inotify` system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the `who-data` information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim
'''
import os

import pytest
from wazuh_testing.fim import LOG_FILE_PATH, regular_file_cud, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# Marks

pytestmark = pytest.mark.tier(level=3)

# variables

test_directories = [os.path.join(PREFIX, 'testdir1'), os.path.join(PREFIX, 'testdir2')]

directory_str = ','.join(test_directories)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf.yaml')
testdir1 = test_directories[0]

file_list = []
for i in range(10000):
    file_list.append(f'regular_{i}')

wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

# configurations

monitoring_modes = ['realtime', 'whodata']
conf_params, conf_metadata = generate_params(extra_params={'TEST_DIRECTORIES': directory_str,
                                                           'REPORT_CHANGES': {'report_changes': 'no'},
                                                           'MODULE_NAME': __name__},
                                             modes=monitoring_modes)

configurations = load_wazuh_configurations(configurations_path, __name__, params=conf_params, metadata=conf_metadata)


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests

@pytest.mark.benchmark
@pytest.mark.parametrize('files, folder, tags_to_apply', [
    (file_list[0:10], testdir1, {'ossec_conf'}),
    (file_list[0:100], testdir1, {'ossec_conf'}),
    (file_list[0:1000], testdir1, {'ossec_conf'}),
    (file_list, testdir1, {'ossec_conf'})
])
def test_benchmark_regular_files(files, folder, tags_to_apply, get_configuration,
                                 configure_environment, restart_syscheckd,
                                 wait_for_fim_start):
    '''
    description: Check if the `wazuh-syscheckd` daemon detects CUD events (`added`, `modified`, and `deleted`)
                 in a certain volume of file changes. For this purpose, the test will monitor a folder with
                 multiple testing files and perform modifications on them (add, modify and delete). Finally,
                 the test will verify that all FIM events have been generated for each change made
                 to each file before the set timeout expires.

    wazuh_min_version: 4.2

    parameters:
        - files:
            type: list
            brief: List of regular files to be created.
        - folder:
            type: str
            brief: Monitored directory where the testing files will be created.
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
            brief: Clear the `ossec.log` file and start a new monitor.
        - wait_for_fim_start:
            type: fixture
            brief: Wait for realtime start, whodata start, or end of initial FIM scan.

    assertions:
        - Verify that `FIM` CUD events are generated for each modified file before the specified time expires.

    input_description: A test case (ossec_conf) is contained in external `YAML` file (wazuh_conf.yaml)
                       which includes configuration settings for the `wazuh-syscheckd` daemon and, it
                       is combined with the testing files to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' (`added`, `modified`, and `deleted` events)

    tags:
        - realtime
        - who-data
    '''
    check_apply_test(tags_to_apply, get_configuration['tags'])
    min_timeout = 30

    regular_file_cud(folder, wazuh_log_monitor, file_list=files,
                     min_timeout=min_timeout, triggers_event=True)
