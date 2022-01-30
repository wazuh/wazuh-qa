'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. Specifically, these tests will check if FIM monitors newly added directories
       that match a wildcard used in the configuration.
       The FIM capability is managed by the 'wazuh-syscheckd' daemon, which checks configured files
       for changes to the checksums, permissions, and ownership.

tier: 0

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
    - Windows Server 2019
    - Windows Server 2016
    - Windows Server 2012
    - Windows Server 2003
    - Windows XP

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
import sys
import pytest
from wazuh_testing import global_parameters
from wazuh_testing.fim import LOG_FILE_PATH, regular_file_cud, generate_params
from wazuh_testing.tools import PREFIX
from wazuh_testing.tools.configuration import load_wazuh_configurations, check_apply_test
from wazuh_testing.tools.monitoring import FileMonitor

# marks

pytestmark = pytest.mark.tier(level=0)

# variables

test_folder = os.path.join(PREFIX, 'test_folder')
test_directories = [test_folder]
matched_dirs = ['simple1', 'stars123']
test_subdirectories = matched_dirs + ['not_monitored_directory']
expressions = [os.path.join(test_folder, 'simple?'),
               os.path.join(test_folder, 'star*')]
expresion_str = ','.join(expressions)
wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_conf_wildcards.yml')

# configurations

conf_params = {'TEST_WILDCARDS': expresion_str}
parameters, metadata = generate_params(extra_params=conf_params)
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)


def extra_configuration_before_yield():
    for sub_directory in test_subdirectories:
        if not os.path.exists(os.path.join(test_folder, sub_directory)):
            os.mkdir(os.path.join(test_folder, sub_directory))


# fixtures

@pytest.fixture(scope='module', params=configurations)
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# tests
@pytest.mark.skip(reason="It will be blocked by #2174, when it was solve we can enable again this test")
@pytest.mark.parametrize('subfolder_name', test_subdirectories)
@pytest.mark.parametrize('file_name', ['regular_1'])
@pytest.mark.parametrize('tags_to_apply', [{'ossec_conf_wildcards'}])
def test_basic_usage_wildcards(subfolder_name, file_name, tags_to_apply,
                               get_configuration, configure_environment, restart_syscheckd, wait_for_fim_start):
    '''
    description: Check if the number of directories to monitor grows when using wildcards to specify them.
                 For this purpose, the test creates a set of directories that match the wildcard expressions
                 and ones that do not match the expressions set in the directories to be monitored.
                 Then, the test will create, modify and delete files inside a folder given as an argument.
                 Finally, the test will wait for events only if the folder where the changes are made
                 matches the expression previously set in the 'wazuh-syscheckd' daemon configuration.

    wazuh_min_version: 4.2.0

    parameters:
        - subfolder_name:
            type: str
            brief: Path to the subdirectory in the monitored folder.
        - filename:
            type: str
            brief: Name of the testing file that will be created in the subfolder.
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
            brief: Wait until the first FIM scan is completed.

    assertions:
        - Verify that FIM monitors newly added directories that match a wildcard used in the configuration.

    input_description: A test case (ossec_conf_wildcards) is contained in external YAML file
                       (wazuh_conf_wildcards.yaml) which includes configuration settings for
                       the 'wazuh-syscheckd' daemon and, it is combined with the testing
                       directories to be monitored defined in this module.

    expected_output:
        - r'.*Sending FIM event: (.+)$' ('added', 'modified' and 'deleted' events)

    tags:
        - scheduled
    '''
    if sys.platform == 'win32':
        if '?' in file_name or '*' in file_name:
            pytest.skip("Windows can't create files with wildcards.")
    check_apply_test(tags_to_apply, get_configuration['tags'])

    folder = os.path.join(test_folder, subfolder_name)
    regular_file_cud(folder, wazuh_log_monitor, file_list=[file_name],
                     time_travel=get_configuration['metadata']['fim_mode'] == 'scheduled',
                     min_timeout=global_parameters.default_timeout, triggers_event=subfolder_name in matched_dirs)
